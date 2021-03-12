#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef LIBPCAP_AVAILABLE
#include <pcap.h>
#include <pthread.h>
#else
#include "daq_dlt.h"
#endif

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>

#include "daq_module_api.h"
#include "dpdk_port_conf.h"
#include "dpdk_param.h"

#define INJECT_BUF_NUM (1024*4)
#define POOL_NAME_LEN (64)
#define BURST_SIZE (32)
#define DESC_POOL_NUM (2048)
#define SET_ERROR(modinst, ...)    daq_base_api.set_errbuf(modinst, __VA_ARGS__)

#define HIGH_PERF_ENABLE (1)
#define DAQ_DPDK_VERSION 1915
#define MEMPOOL_CACHE_SIZE  (64)
typedef struct _dpdk_packet_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    unsigned int length;
    struct _dpdk_packet_pkt_desc *next;
} DPDKPacketPktDesc;

typedef struct _dpdk_packet_msg_pool
{
    DPDKPacketPktDesc *pool;
    DPDKPacketPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} DPDKPacketMsgPool;

typedef struct _dpdk_packet_context
{
    /* Configuration */
	uint16_t port_id;
	uint16_t queue_id;
    char *filter;
    int snaplen;	
    int timeout;
    uint8_t debug;
    /* State */
    DAQ_ModuleInstance_h modinst;
	struct timeval ts;
#ifdef LIBPCAP_AVAILABLE
    struct bpf_program fcode;
#endif
    DPDKPacketMsgPool pool;
    struct rte_mempool *inject_mbuf_pool;
    volatile uint8_t interrupted;
    DAQ_Stats_t stats;	
}__attribute__((aligned(64))) DPDK_Packet_Context_t;

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
	DAQ_VERDICT_PASS,		/* DAQ_VERDICT_PASS */
	DAQ_VERDICT_BLOCK,		/* DAQ_VERDICT_BLOCK */
	DAQ_VERDICT_PASS,		/* DAQ_VERDICT_REPLACE */
	DAQ_VERDICT_PASS,		/* DAQ_VERDICT_WHITELIST */
	DAQ_VERDICT_BLOCK,		/* DAQ_VERDICT_BLACKLIST */
	DAQ_VERDICT_PASS,		/* DAQ_VERDICT_IGNORE */
	DAQ_VERDICT_BLOCK		/* DAQ_VERDICT_RETRY */
};

static DAQ_BaseAPI_t daq_base_api;
static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t dpdk_start_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t dpdk_stop_mutex = PTHREAD_MUTEX_INITIALIZER;


static DAQ_VariableDesc_t dpdk_variable_descriptions[] = {
    { "debug", "Enable debugging output to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

static void destroy_packet_pool(DPDK_Packet_Context_t *dpdk_pctx)
{
    DPDKPacketMsgPool *pool = &dpdk_pctx->pool;
    if (pool->pool)
    {
        while (pool->info.size > 0)
            free(pool->pool[--pool->info.size].data);
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

static int create_packet_pool(DPDK_Packet_Context_t *dpdk_pctx, unsigned size)
{
    DPDKPacketMsgPool *pool = &dpdk_pctx->pool;
    pool->pool = calloc(sizeof(DPDKPacketPktDesc), size);
    if (!pool->pool)
    {
        SET_ERROR(dpdk_pctx->modinst, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
                __func__, sizeof(DPDKPacketPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(DPDKPacketPktDesc) * size;
    while (pool->info.size < size)
    {
        /* Allocate packet data and set up descriptor */
        DPDKPacketPktDesc *desc = &pool->pool[pool->info.size];
        desc->data = malloc(dpdk_pctx->snaplen);
        if (!desc->data)
        {
            SET_ERROR(dpdk_pctx->modinst, "%s: Could not allocate %d bytes for a packet descriptor message buffer!",
                    __func__, dpdk_pctx->snaplen);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += dpdk_pctx->snaplen;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(desc->pkthdr);
        msg->hdr = &desc->pkthdr;
        msg->data = desc->data;
        msg->owner = dpdk_pctx->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

static int dpdk_daq_module_load(const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION || base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;
    return DAQ_SUCCESS;
}

static int dpdk_daq_module_unload(void)
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int dpdk_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = dpdk_variable_descriptions;
    return sizeof(dpdk_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}


static int dpdk_daq_instantiate(const DAQ_ModuleConfig_h modcfg, DAQ_ModuleInstance_h modinst, void **ctxt_ptr)
{
	int rval=DAQ_SUCCESS,ret;
    DPDK_Packet_Context_t *dpdk_pctx;
	static int first_time_init = 1,pool_index = 0;
	char pool_name[64];
    dpdk_pctx = calloc(1, sizeof(DPDK_Packet_Context_t));
    if (!dpdk_pctx)
    {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new DPDK Packet context!", __func__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

	//dpdk init
	if (first_time_init)
	{
		first_time_init = 0;
		printf("in eal init!\n");
		if(dpdk_conf_parse() != 0)	
		{
			printf("conf parse error!\n");
			goto err;
		}
		
		ret = rte_eal_init(dpdk_get_param_cnt(), dpdk_get_param());
		if (ret < 0)
		{
			printf( "Cannot init EAL\n");			
			goto err;
		}
		dpdk_port_setup();
	}

	snprintf(pool_name,POOL_NAME_LEN,"inject_mbuf_pool_%d",pool_index);
	pool_index++;

	dpdk_pctx->inject_mbuf_pool = rte_pktmbuf_pool_create(pool_name, INJECT_BUF_NUM, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 1);
	if (dpdk_pctx->inject_mbuf_pool == NULL)
	{
		printf( "%s:%s Couldn't create mbuf pool!\n", __FUNCTION__,pool_name);
		rval = DAQ_ERROR_NOMEM;
		goto err;
	}

	if (daq_base_api.config_get_mode(modcfg) != DAQ_MODE_PASSIVE)
	{
		uint16_t ports = dpdk_get_port_num();
		if (ports % 2)
		{
			printf("DAQ_MODE_INLINE ports should bi dual \n");
			goto err;
		}
	}

	//config info get
	const char *varKey, *varValue;
	daq_base_api.config_first_variable(modcfg, &varKey, &varValue);
	while (varKey)
	{
		if (!strcmp(varKey, "debug"))
			dpdk_pctx->debug = 1;								
		daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
	}
	dpdk_pctx->stats.packets_received = 0;
	dpdk_pctx->snaplen = daq_base_api.config_get_snaplen(modcfg);
	dpdk_pctx->timeout = (int) daq_base_api.config_get_timeout(modcfg);
	if (dpdk_pctx->timeout == 0)
		dpdk_pctx->timeout = -1;
	gettimeofday(&dpdk_pctx->ts, NULL);

    /* Finally, create the message buffer pool. */
    uint32_t pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    if (pool_size == 0)
        pool_size = DESC_POOL_NUM;
	
    if ((rval = create_packet_pool(dpdk_pctx, pool_size)) != DAQ_SUCCESS)
        goto err;


	dpdk_get_port_and_queue(&dpdk_pctx->port_id,&dpdk_pctx->queue_id);

    dpdk_pctx->modinst = modinst;
	*ctxt_ptr = dpdk_pctx;
	return rval;
err:
	if (dpdk_pctx)
		free(dpdk_pctx);
	
    return rval;
}

static void dpdk_daq_destroy(void *handle)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;

#ifdef LIBPCAP_AVAILABLE
    pcap_freecode(&dpdk_pctx->fcode);
#endif
	if(dpdk_pctx)
    	free(dpdk_pctx);
	
    destroy_packet_pool(dpdk_pctx);
}

static int dpdk_daq_set_filter(void *handle, const char *filter)
{
#ifdef LIBPCAP_AVAILABLE
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;
    struct bpf_program fcode;

    if (dpdk_pctx->filter)
        free(dpdk_pctx->filter);

    dpdk_pctx->filter = strdup(filter);
    if (!dpdk_pctx->filter)
    {
        SET_ERROR(dpdk_pctx->modinst, "%s: Couldn't allocate memory for the filter string!", __func__);
        return DAQ_ERROR;
    }

    pthread_mutex_lock(&bpf_mutex);
    if (pcap_compile_nopcap(dpdk_pctx->snaplen, DLT_EN10MB, &fcode, dpdk_pctx->filter, 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
        pthread_mutex_unlock(&bpf_mutex);
        SET_ERROR(dpdk_pctx->modinst, "%s: BPF state machine compilation failed!", __func__);
        return DAQ_ERROR;
    }
    pthread_mutex_unlock(&bpf_mutex);

    pcap_freecode(&dpdk_pctx->fcode);
    dpdk_pctx->fcode.bf_len = fcode.bf_len;
    dpdk_pctx->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
#else
    return DAQ_ERROR_NOTSUP;
#endif
}

static int dpdk_daq_start(void *handle)
{
	static int first_time_start = 1;
	DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;
    pthread_mutex_lock(&dpdk_start_mutex);
	if (first_time_start)
	{
		first_time_start = 0;
		//first start
		dpdk_port_start();				
	}
    pthread_mutex_unlock(&dpdk_start_mutex);
    memset(&dpdk_pctx->stats, 0, sizeof(DAQ_Stats_t));
	printf("THREAD runnging on Port:%d Queue:%d!\n",dpdk_pctx->port_id,dpdk_pctx->queue_id);
    return DAQ_SUCCESS;
}

static int dpdk_inject_packet(DPDK_Packet_Context_t *dpdk_pctx, DAQ_Msg_t *msg,uint16_t out_port_id, uint16_t out_queue_id,const uint8_t *data, uint32_t data_len)
{
#ifdef HIGH_PERF_ENABLE
	struct rte_mbuf *mbuf = (struct rte_mbuf *)msg->priv_mbuf;
	rte_pktmbuf_data_len(mbuf) = data_len;
	//rte_pktmbuf_dump(stdout,mbuf,mbuf->pkt_len);
	uint16_t nb_tx = rte_eth_tx_burst(out_port_id, out_queue_id, &mbuf, 1);

#else
	struct rte_mbuf *m;

	m = rte_pktmbuf_alloc(dpdk_pctx->inject_mbuf_pool);
	if (!m)
	{
		printf("%s: Couldn't allocate memory for packet.",__FUNCTION__);
		return DAQ_ERROR_NOMEM;
	}
	rte_memcpy(rte_pktmbuf_mtod(m, void *), data, data_len);
	rte_pktmbuf_data_len(m) = data_len;

	uint16_t nb_tx = rte_eth_tx_burst(out_port_id, out_queue_id, &m, 1);
	
	if (unlikely(nb_tx == 0))
	{
		printf( "%s: Couldn't send packet. Try again.", __FUNCTION__);
		rte_pktmbuf_free(m);
		return DAQ_ERROR_AGAIN;
	}
	rte_pktmbuf_free(m);

#endif
	dpdk_pctx->stats.packets_injected++;

    return DAQ_SUCCESS;
}

static int dpdk_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;

    if (type != DAQ_MSG_TYPE_PACKET)
        return DAQ_ERROR_NOTSUP;

    return dpdk_inject_packet(dpdk_pctx,NULL,dpdk_pctx->port_id,dpdk_pctx->queue_id,data,data_len);
}

static int dpdk_daq_inject_relative(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;	
	uint16_t reverse_port = dpdk_pctx->port_id;
	if (reverse)
		reverse_port = dpdk_pctx->port_id % 2 ? (dpdk_pctx->port_id - 1):(dpdk_pctx->port_id + 1);
	
	return dpdk_inject_packet(dpdk_pctx,msg,reverse_port,dpdk_pctx->queue_id,data,data_len);
}

static int dpdk_daq_interrupt(void *handle)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;
    dpdk_pctx->interrupted = 1;

    return DAQ_SUCCESS;
}

static int dpdk_daq_stop(void *handle)
{
	static int first_time_stop = 1;

    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;	
    pthread_mutex_lock(&dpdk_stop_mutex);

	if (first_time_stop) 
	{
		first_time_stop = 0;
		rte_eth_dev_stop(dpdk_pctx->port_id);
		rte_eth_dev_close(dpdk_pctx->port_id);
	}
    pthread_mutex_unlock(&dpdk_stop_mutex);
    return DAQ_SUCCESS;
}

static int dpdk_daq_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{

    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;

    /* Only supports GET_DEVICE_INDEX for now */
    if (cmd != DIOCTL_GET_DEVICE_INDEX || arglen != sizeof(DIOCTL_QueryDeviceIndex))
        return DAQ_ERROR_NOTSUP;

    DIOCTL_QueryDeviceIndex *qdi = (DIOCTL_QueryDeviceIndex *) arg;

    if (!qdi->device)
    {
        SET_ERROR(dpdk_pctx->modinst, "No device name to find the index of!");
        return DAQ_ERROR_INVAL;
    }

	//undo:
    qdi->index = 0;
    return DAQ_SUCCESS; 
}

static int dpdk_daq_get_stats(void *handle, DAQ_Stats_t *stats)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;
    rte_memcpy(stats, &dpdk_pctx->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

static void dpdk_daq_reset_stats(void *handle)
{
	DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;
    memset(&dpdk_pctx->stats, 0, sizeof(DAQ_Stats_t));
}

static int dpdk_daq_get_snaplen(void *handle)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;
    return dpdk_pctx->snaplen;
}

static uint32_t dpdk_daq_get_capabilities(void *handle)
{
    uint32_t capabilities = DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
                            DAQ_CAPA_UNPRIV_START | DAQ_CAPA_INTERRUPT | DAQ_CAPA_DEVICE_INDEX;
#ifdef LIBPCAP_AVAILABLE
    capabilities |= DAQ_CAPA_BPF;
#endif
    return capabilities;
}

static int dpdk_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static unsigned dpdk_daq_msg_receive(void *handle, const unsigned max_recv, const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    unsigned idx = 0,loop = 0;
	uint8_t *data;
    uint16_t len,max_recv_ok = max_recv;
	
	struct rte_mbuf *bufs[BURST_SIZE];
	if (dpdk_pctx->interrupted)
	{
		dpdk_pctx->interrupted = 0;
		status = DAQ_RSTAT_INTERRUPTED;
		goto err;
	}

	if (max_recv > BURST_SIZE)
		max_recv_ok = BURST_SIZE;

	uint16_t nb_rx = rte_eth_rx_burst(dpdk_pctx->port_id, dpdk_pctx->queue_id, bufs, max_recv_ok);
	dpdk_pctx->stats.packets_received += nb_rx;

	for (loop = 0; loop < nb_rx; loop++)
    {    
    	//printf("port:%d queue:%d\n",dpdk_pctx->port_id,dpdk_pctx->queue_id);
		data = rte_pktmbuf_mtod(bufs[loop], void *);
		len = rte_pktmbuf_data_len(bufs[loop]);
		
		//rte_pktmbuf_dump(stdout,bufs[loop],bufs[loop]->pkt_len);
#if 0
#ifdef LIBPCAP_AVAILABLE			
		if (dpdk_pctx->fcode.bf_insns && bpf_filter(dpdk_pctx->fcode.bf_insns, data, len, len) == 0)
		{
			dpdk_pctx->stats.packets_filtered++;	
			rte_pktmbuf_free(bufs[loop]);
			continue;
		}
#endif
#endif

		DPDKPacketPktDesc *desc = dpdk_pctx->pool.freelist;
		if (!desc)
		{
			printf("1111 addr:%p availabel:%d\n",desc,dpdk_pctx->pool.info.available);
			rte_pktmbuf_free(bufs[loop]);
			status = DAQ_RSTAT_NOBUF;
			break;
		}

		//undo: not copy data to desc,should store the rte_mbuf desc to data,and later free it.

        desc->length = len;

        /* Next, set up the DAQ message.  Most fields are prepopulated and unchanging. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->data_len = len;

#ifdef HIGH_PERF_ENABLE
		msg->data = data;
		msg->priv_mbuf = bufs[loop];
#else
		rte_memcpy(desc->data, data, len);
		rte_pktmbuf_free(bufs[loop]);
#endif
        /* Then, set up the DAQ packet header. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ts.tv_sec = 0;
        pkthdr->ts.tv_usec = 0;
        pkthdr->pktlen = len;
        pkthdr->ingress_index = dpdk_pctx->port_id;
        pkthdr->egress_index = 
			dpdk_pctx->port_id % 2 ? (dpdk_pctx->port_id - 1):(dpdk_pctx->port_id + 1);
        pkthdr->flags = 0;
   
        dpdk_pctx->pool.freelist = desc->next;
        desc->next = NULL;
        dpdk_pctx->pool.info.available--;
        msgs[idx] = &desc->msg;
        idx++;	
		//rte_pktmbuf_dump(stdout,bufs[loop],bufs[loop]->pkt_len);
		//uint16_t nb_tx = rte_eth_tx_burst(dpdk_pctx->port_id, dpdk_pctx->queue_id, &bufs[loop], 1);
    }
#if 0
	if (!nb_rx && (dpdk_pctx->timeout != -1 ))
	{
		struct timeval now;
	

	/* If time out, return control to the caller. */
		gettimeofday(&now, NULL);
		if (now.tv_sec > dpdk_pctx->ts.tv_sec ||
			(now.tv_usec - dpdk_pctx->ts.tv_usec) > dpdk_pctx->timeout * 1000)
			status = DAQ_RSTAT_TIMEOUT;
		else
			gettimeofday(&dpdk_pctx->ts, NULL);
	}
#endif
err:
    *rstat = status;
    return idx;
}

static int dpdk_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;

	DPDKPacketPktDesc *desc = (DPDKPacketPktDesc *) msg->priv;

	/* Sanitize and enact the verdict. */
	if (verdict >= MAX_DAQ_VERDICT)
		verdict = DAQ_VERDICT_PASS;
	
	dpdk_pctx->stats.verdicts[verdict]++;
	verdict = verdict_translation_table[verdict];
	if (verdict == DAQ_VERDICT_PASS)
	{
		dpdk_daq_inject_relative(dpdk_pctx,msg,msg->data,msg->data_len,0);
	}
	else
	{
#ifdef HIGH_PERF_ENABLE
		struct rte_mbuf *mbuf = (struct rte_mbuf *)msg->priv_mbuf;
		//rte_pktmbuf_dump(stdout,mbuf,mbuf->pkt_len);		
		//uint16_t nb_tx = rte_eth_tx_burst(dpdk_pctx->port_id, dpdk_pctx->queue_id, &mbuf, 1);
		rte_pktmbuf_free(mbuf);
#endif

	}
	desc->next = dpdk_pctx->pool.freelist;
	dpdk_pctx->pool.freelist = desc;
	dpdk_pctx->pool.info.available++;
	return DAQ_SUCCESS;
}

static int dpdk_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info)
{
    DPDK_Packet_Context_t *dpdk_pctx = (DPDK_Packet_Context_t *) handle;
    *info = dpdk_pctx->pool.info;

    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t dpdk_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_DPDK_VERSION,
    /* .name = */ "dpdk",
    /* .type = */ DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ dpdk_daq_module_load,
    /* .unload = */ dpdk_daq_module_unload,
    /* .get_variable_descs = */ dpdk_daq_get_variable_descs,
    /* .instantiate = */ dpdk_daq_instantiate,
    /* .destroy = */ dpdk_daq_destroy,
    /* .set_filter = */ dpdk_daq_set_filter,
    /* .start = */ dpdk_daq_start,
    /* .inject = */ dpdk_daq_inject,
    /* .inject_relative = */ dpdk_daq_inject_relative,
    /* .interrupt = */ dpdk_daq_interrupt,
    /* .stop = */ dpdk_daq_stop,
    /* .ioctl = */ dpdk_daq_ioctl,
    /* .get_stats = */ dpdk_daq_get_stats,
    /* .reset_stats = */ dpdk_daq_reset_stats,
    /* .get_snaplen = */ dpdk_daq_get_snaplen,
    /* .get_capabilities = */ dpdk_daq_get_capabilities,
    /* .get_datalink_type = */ dpdk_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ dpdk_daq_msg_receive,
    /* .msg_finalize = */ dpdk_daq_msg_finalize,
    /* .get_msg_pool_info = */ dpdk_daq_get_msg_pool_info,
};


