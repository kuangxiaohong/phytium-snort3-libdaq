#ifndef __DPDK_PARAM__
#define __DPDK_PARAM__

typedef struct dpdk_port_conf
{
	int queue_num;
	int mtu;
	int rss_tuple;
	int jumbo;
}dpdk_port_conf_t;

/**
 *dpdk�����ļ�����
 *
 * @param  
 * 	 
 * @return 0�ɹ�������ʧ��
 *   
 */
int dpdk_conf_parse(void);

/**
 *dpdk���ò���������ȡ
 *
 * @param  
 * 	 
 * @return �������ò�������
 *   
 */
int dpdk_get_param_cnt(void);

/**
 *dpdk���ò�����ȡ
 *
 * @param  
 * 	 
 * @return �������ò���
 *   
 */
char **dpdk_get_param(void);

/**
 *dpdk�������ø�����ȡ
 *
 * @param  
 * 	 
 * @return �����������ø���
 *   
 */
int dpdk_get_port_cnt(void);

/**
 *dpdk����������Ϣ��ȡ
 *
 * @param  
 * 	 
 * @return ����ĳ������������Ϣ
 *   
 */
dpdk_port_conf_t* dpdk_get_port_conf(int port_id);

#endif

