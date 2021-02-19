#ifndef __DPDK_PORT_CONF__
#define __DPDK_PORT_CONF__

#include "stdint.h"

//can get from dpdk param
#define NB_MBUF             (1024*1024) 
#define NB_SOCKETS        (8)

/**
 * ���ڽ�������ʼ��
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_setup(void);

/**
 * ���������հ�
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_start(void);

/**
 * ��ȡĳ���ڵĶ�����
 *
 * @param port_id
 *   ����id
 * @return �������ڶ�����
 *   
 */
int dpdk_get_port_queue_num(int port_id);

/**
 * ��ȡ������
 *
 * @param 
 *   
 * @return ����������
 *   
 */
int dpdk_get_port_num(void);

/**
 *ÿ����һ�η���һ�����ںͶ��У����ڶ��̴߳���
 *
 * @param  *out_port
 * 	���ڷ���ֵ
 * @param  *out_queue
 * 	���з���ֵ
 *   
 * @return 
 *   
 */
int dpdk_get_port_and_queue(uint16_t *out_port,uint16_t *out_queue);

/**
 *��ӡ����������Ϣ
 *
 * @param  
 * 	 
 * @return 
 *   
 */
void dpdk_ports_print(void);

/**
 * �������link״̬
 *
 * @param port_num
 *   ���ڸ���
 * @param port_mask
 *   ��������
 * @return
 *   
 */
void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask);

/**
 *��ȡ���ж��и���
 *
 * @param  
 * 	 
 * @return �������ж�����
 *   
 */
int dpdk_get_port_queue_total(void);


/**
 * ��������������Ϣ��ȷ�����ڸ����Ͷ����������������ڳ�ʼ��
 *
 * @param 
 *   
 * @return
 *   
 */
void dpdk_port_setup_proc(void);

#endif
