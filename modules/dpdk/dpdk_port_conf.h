#ifndef __DPDK_PORT_CONF__
#define __DPDK_PORT_CONF__

#include "stdint.h"

//can get from dpdk param
#define NB_MBUF             (1024*1024) 
#define NB_SOCKETS        (8)

/**
 * 网口建立并初始化
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_setup(void);

/**
 * 网口启动收包
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_start(void);

/**
 * 获取某网口的队列数
 *
 * @param port_id
 *   网口id
 * @return 返回网口队列数
 *   
 */
int dpdk_get_port_queue_num(int port_id);

/**
 * 获取网口数
 *
 * @param 
 *   
 * @return 返回网口数
 *   
 */
int dpdk_get_port_num(void);

/**
 *每调用一次返回一个网口和队列，用于多线程处理
 *
 * @param  *out_port
 * 	网口返回值
 * @param  *out_queue
 * 	队列返回值
 *   
 * @return 
 *   
 */
int dpdk_get_port_and_queue(uint16_t *out_port,uint16_t *out_queue);

/**
 *打印所有网口信息
 *
 * @param  
 * 	 
 * @return 
 *   
 */
void dpdk_ports_print(void);

/**
 * 检测网口link状态
 *
 * @param port_num
 *   网口个数
 * @param port_mask
 *   网口掩码
 * @return
 *   
 */
void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);

/**
 *获取所有队列个数
 *
 * @param  
 * 	 
 * @return 返回所有队列数
 *   
 */
int dpdk_get_port_queue_total(void);


/**
 * 根据网口配置信息来确定网口个数和队列数，并进行网口初始化
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_setup_proc(void);

#endif
