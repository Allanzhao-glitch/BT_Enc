#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/signalfd.h>
#include <sys/queue.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <glib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <dbus/dbus.h>
#include "gatt_ble.h"
#include "gdbus.h"
#include "agl_midware_api.h"
#include "agl_log_api.h"
#include "blufi.h"
#include "esp_blufi.h"
#include "esp_crc.h"
#include "hci_lib.h"
#include "bluetooth.h"
#include "esp_blufi_api.h"
#include "msg_api.h"
#include "cJSON.h"
#include "app_interaction.h"
#include "blufi_int.h"
#include "btc_blufi_prf.h"
#include "user_pb_drv.h"
#include "ble_interface.h"
#include "ble_statistics.h"
#include "wifiserv_interface.h"
#include "netdev_type.h"
#include "ble_hci_fun.h"
#include "app_server.h"
#include "aes256.h"
#include "blufi_data_encry.h"
static int8_t communication_stage = 0;


char *aad = "12345678";
unsigned char key[KEY_SIZE] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 
    0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 
    0x55, 0x56
};
/**
 * 数据传输协议
 */
typedef struct {
    uint32_t data_len;      // 加密数据长度
    uint32_t tag_len;       // 标签长度（通常是16）
    uint8_t data[];         // 变长加密数据
} EncryptedDataHeader;

/**
 * 动态密钥交换协议
 */
typedef struct {
    uint8_t client_pub_len;  // 加密数据长度
    uint8_t is_change;       // 密钥配对成功
    uint8_t data[];         // 公钥
}KeyMatchHeader;
/**
 * 共享密钥
 */
typedef struct {
   char share_key[1024];
   uint32_t share_key_len; 
}ShareKey;
static ShareKey *sharekey = NULL;
static pthread_mutex_t sharekey_mutex = PTHREAD_MUTEX_INITIALIZER; // 全局共享密钥锁
static pthread_mutex_t communication_stage_mutex = PTHREAD_MUTEX_INITIALIZER; // 全局通信阶段标记锁
// void bin_to_hex(const uint8_t *bin, size_t len, char *output) {
//     if (!bin || !output || len == 0) {
//         BLE_INFO("clinet hex data error ");
//         return; // 或者记录错误日志
//     }

//     for (size_t i = 0; i < len; ++i) {
//         snBLE_INFO(output + (i * 2), 3, "%02x", bin[i]); // 保证最多写入 2+1 字节
//     }
//     output[len * 2] = '\0';
// }

/**
 * 更新通信阶段
 * @param stage 通信阶段标记
 */
void update_communication_stage(uint8_t stage)
{
    pthread_mutex_lock(&communication_stage_mutex);
    communication_stage = stage;
    pthread_mutex_unlock(&communication_stage_mutex);
}
/**
 * 获取当前阶段
 * @return 当前通信阶段
 */
uint8_t get_communication_stage()
{
    return communication_stage;
}
/**
 * 更新共享密钥
 * @param sharekey_t 新共享密钥
 * @param key_len 新共享密钥长度
 */
static void update_sharekey(const ShareKey *sharekey_t, size_t key_len) 
{
    pthread_mutex_lock(&sharekey_mutex);
    // 1. 分配新内存
    ShareKey *new_sharekey = malloc(sizeof(ShareKey) + key_len);
    if (!new_sharekey) {
        perror("malloc failed");
        return;
    }

    // 2. 拷贝数据到新内存（原子操作）
    new_sharekey->share_key_len = key_len;
    memcpy(new_sharekey->share_key, 
          sharekey_t->share_key, 
          key_len);
    
    // 4. 替换旧指针（原子指针赋值）
    ShareKey *old_sharekey = sharekey;
    sharekey = new_sharekey;

    if (old_sharekey) {
        explicit_bzero(old_sharekey,  // 清空敏感数据
                      sizeof(ShareKey) + old_sharekey->share_key_len);
        free(old_sharekey);
    }
    pthread_mutex_unlock(&sharekey_mutex);
}
/**
 * 销毁共享密钥
 */
static void destroy_sharekey() 
{
    pthread_mutex_lock(&sharekey_mutex);
    if (sharekey) {
        explicit_bzero(sharekey, 
                      sizeof(ShareKey) + sharekey->share_key_len);
        free(sharekey);
        sharekey = NULL;
    }
    pthread_mutex_unlock(&sharekey_mutex);
}



/**
 * 配对阶段
 * 接收客户端发的加密公钥，解密生成共享密钥，
 * 服务端生成加密公钥发送给客户端，客户端解密生成共享密钥，
 * 下发配对状态，完成配对
 * @param blufi_data blufi数据
 * @param blufi_data_len blufi数据长度
 */
gboolean key_generation(uint8_t *blufi_data, int *blufi_data_len)
{
    char *plaintext = NULL; // 解密之后的客户端公钥
    char *enplaintext = NULL; // 加密之后的服务端公钥
    uint8_t type = BLUFI_BUILD_TYPE(BLUFI_TYPE_DATA, BLUFI_TYPE_DATA_SUBTYPE_CUSTOM_DATA);
    uint8_t *cp = g_memdup(blufi_data, *blufi_data_len);
    KeyMatchHeader *clinet_pari_data = (KeyMatchHeader *)cp;
    static uint8_t pair_count = 0;
    const char *error = "error";
    KeyMatchHeader *response_cerror_lient_data =  malloc(sizeof(KeyMatchHeader) + strlen(error));// 回复客户端消息体错误
    memset(response_cerror_lient_data,0,sizeof(KeyMatchHeader) + strlen(error));
    response_cerror_lient_data->is_change = PAIR_STAGE_FAIL;
    memcpy(response_cerror_lient_data->data, error, strlen(error));
    response_cerror_lient_data->client_pub_len = strlen(error);
    BLE_INFO("\n ====================================key_generation orgin data start===============================================\n");
    for(int i = 0; i <  *blufi_data_len; i++)
    {
        BLE_INFO("%02x",blufi_data[i]);
    }
    BLE_INFO("\n ====================================key_generation orgin data end===============================================\n");
    if(pair_count > 3)
    {
        BLE_ERROR("pari error count:%d,ble is disconnect!",pair_count);
        pair_count = 0;
        // ble_disconnect_func();
    }
    if(clinet_pari_data == NULL)
    {
        pair_count ++;
        BLE_INFO("clinet_pari_data is null");
        return false;
    }
    if(clinet_pari_data->is_change == PAIR_STAGE_STATUS_SUCC)
    {
        communication_stage = STAGE_COMM;
        BLE_INFO("Pairing successful");
        return true;
    }
    if(clinet_pari_data->is_change != PAIR_STAGE_WAIT_CONFIRM)
    {
        BLE_INFO("Pairing failed:%d",clinet_pari_data->is_change);
        btc_blufi_send_encap(type,(uint8_t *)response_cerror_lient_data, sizeof(KeyMatchHeader)+strlen(error));
        pair_count ++;
        return false;
    }
    if(communication_stage == 0 && sharekey != NULL)
    {
        destroy_sharekey();
    }
    if(clinet_pari_data -> client_pub_len == 0) {
        BLE_INFO("client_pub_len is 0,key create error");
        return false;
    }
    // char *output = malloc(clinet_pari_data->client_pub_len);
    BLE_INFO("======================================================================================================\n");
    BLE_INFO("======================================================================================================\n");
    BLE_INFO("======================================================================================================\n");
    
    for(int i = 0; i <  clinet_pari_data->client_pub_len; i++)
    {
        BLE_INFO("%02x",clinet_pari_data->data[i]);
    }
    BLE_INFO("\n");

    int len = aes256_decrypt((const char *)clinet_pari_data->data,key, &plaintext,clinet_pari_data->client_pub_len);
    if(len == 0) BLE_INFO("===============aes256_decrypt error! len:%d======================\n",len);
    BLE_INFO("BLE+++++++++++++++++++++++++++ len:%d+++++++++++++clinet_pari_data->client_pub_len:%d++++++++++++++++++++++++\n",len,clinet_pari_data->client_pub_len);
    for(int i = 0; i <  len; i++)
    {
        BLE_INFO("%02x",plaintext[i]);
    }
    BLE_INFO("\n");
    BLE_INFO("BLE------------------------------------------------------------\n");
    if(len != 0)
    {

        size_t local_share_key_len = 0; //服务端共享密钥长度
        size_t server_pub_len = 0;	// 服务端公钥长度
        EC_KEY *server_private_key = generate_ecdh_key(); // 生成服务端私钥
        EC_KEY *key_for_compute = EC_KEY_dup(server_private_key);
        char local_share_key[1024]={0};
        unsigned char *server_pub_key = export_public_key(server_private_key,&server_pub_len); // 根据服务端私钥生成服务端公钥
        local_share_key_len = compute_shared_secret(key_for_compute,(const unsigned char *)plaintext,len,local_share_key); // 创建本地共享密钥
        if(local_share_key_len != 0 && server_pub_len != 0)
        {
            for(int i = 0; i < local_share_key_len; i++)
            {
                BLE_INFO("%02x",local_share_key[i]);
            }
            BLE_INFO("\n");
            ShareKey *sharekey_t = malloc(sizeof(ShareKey) + local_share_key_len);
            if(sharekey_t != NULL)
            {
                sharekey_t->share_key_len = local_share_key_len;
                memcpy(sharekey_t->share_key, local_share_key, local_share_key_len);
                update_sharekey(sharekey_t, local_share_key_len);
                BLE_INFO("==========++++++++++++++++++++++++++++++++_______________________________");
                free(sharekey_t);
            }else {
                BLE_INFO("save sharekey fail !");
                pair_count ++;
                btc_blufi_send_encap(type,(uint8_t *)response_cerror_lient_data, sizeof(KeyMatchHeader)+strlen(error));
                goto clean;
            }

        }else{
            BLE_INFO("create local_share_key:%s error or server_pub_key%s error!",local_share_key,server_pub_key);
            pair_count ++;
            btc_blufi_send_encap(type,(uint8_t *)response_cerror_lient_data, sizeof(KeyMatchHeader)+strlen(error));
            goto clean;
        }
        BLE_INFO("BLE------------------------original_server_pub_key------------------------------------\n");
        for(int i = 0; i < server_pub_len; i++)
        {
            BLE_INFO("%02x",server_pub_key[i]);
        }
        BLE_INFO("\n");
        int server_en_pub_key_len = aes256_encrypt((const char *)server_pub_key,key, &enplaintext);
        
        if(server_en_pub_key_len == 0)
        {
            BLE_INFO("encrypt aes256_encrypt server_pub_key error!");
            btc_blufi_send_encap(type,(uint8_t *)response_cerror_lient_data, sizeof(KeyMatchHeader)+server_pub_len);
            pair_count ++;
            destroy_sharekey();
            goto clean;
        }
        BLE_INFO("send_out_hex:%s\n",enplaintext);
        KeyMatchHeader *response_success_client_data =  malloc(sizeof(KeyMatchHeader) + strlen(enplaintext));// 回复客户端消
        response_success_client_data->is_change = PAIR_STAGE_STATUS_SUCC;
        response_success_client_data->client_pub_len = strlen(enplaintext);
        memcpy(response_success_client_data->data, enplaintext, strlen(enplaintext));
        BLE_INFO("response_success_client_data->client_pub_len:%d\n",response_success_client_data->client_pub_len);
        btc_blufi_send_encap(type,(uint8_t *)response_success_client_data, sizeof(KeyMatchHeader)+strlen(enplaintext));
        if(response_success_client_data)
        {
            free(response_success_client_data);
        }
        if(response_cerror_lient_data)
        {
            free(response_cerror_lient_data);
        }
         
clean:
        if(plaintext)
        {
            free(plaintext);
            plaintext = NULL;
        }
        if (enplaintext)
        {
            free(enplaintext);
            enplaintext = NULL;
        }
        if(server_private_key)
        {
            EC_KEY_free(server_private_key);
        }
        if(server_pub_key)
        {
            OPENSSL_free(server_pub_key);
        }
        if(key_for_compute)
        {
            EC_KEY_free(key_for_compute);
        }
    }
    return true;
}




#if 1
/***
 * 数据通信阶段
 * 解密客户端下发数据
 * @param blufi_data blufi数据
 * @param blufi_data_len blufi数据长度
 */
uint8_t* decrypt_blufi_data(uint8_t *blufi_data, int *blufi_data_len) 
{
    if(sharekey == NULL) return NULL;
    char *plaintext = NULL;
    EncryptedDataHeader *header = (EncryptedDataHeader *)blufi_data;
    uint32_t data_len = header->data_len;
    uint32_t tag_len = header->tag_len;
    if(tag_len != 32 || blufi_data_len == 0){ 
        BLE_ERROR("app send data error data_len:%d,tag_len:%d, all_data_len:%d",data_len,tag_len,*blufi_data_len);
        return NULL;
    }

    BLE_INFO("debug Received data length: %u\n", data_len);
    BLE_INFO("debug Received tag length: %u\n", tag_len);
    const uint8_t *data = blufi_data + sizeof(EncryptedDataHeader);
    const uint8_t *tag = data + data_len;
    // const uint8_t *iv = tag + tag_len;
    BLE_INFO("=================================recv_data_all all_data_len:%d================================\n",*blufi_data_len);
    for(int i = 0; i < *blufi_data_len; i ++)
    {
        BLE_INFO("%02x",blufi_data[i]);
    }
    BLE_INFO("\n=================================recv_data_all_end================================\n");


    BLE_INFO("=================================recv_data data_len:%d================================\n",data_len);
    for(int i = 0; i < data_len; i ++)
    {
        BLE_INFO("%02x",data[i]);
    }
    BLE_INFO("\n");
    BLE_INFO("\n=================================recv_data_end================================\n");
    BLE_INFO("=================================recv_tag tag_len:%d================================\n",tag_len);
    for(int i = 0; i < tag_len; i ++)
    {
        BLE_INFO("%02x",tag[i]);
    }
    BLE_INFO("\n");
    BLE_INFO("\n=================================recv_tag_end================================\n");
    // char *out_hex = NULL;
    // bin_to_hex(blufi_data,*blufi_data_len,out_hex);
    // int len = aes256_decrypt((const char *)out_hex,(const unsigned char*)sharekey->share_key, iv1, &plaintext,strlen(out_hex));
    int len = aes256_gcm_decrypt((const char*)data,(const uint32_t) header -> data_len, (const unsigned char*)sharekey->share_key, aad, (const char*)tag, &plaintext);
    BLE_INFO("decrypt_blufi_data:%d\n",len);
    if (len != 0)
    {
        memset(blufi_data,0,*blufi_data);
        *blufi_data_len = len;
        uint8_t* decrpyt_recv_data = malloc(len);
        memcpy(decrpyt_recv_data, plaintext,len);
        BLE_INFO("+++++++++++++++++++++++++++++++len:%d+++++++++++++++++++++++++++++++++++++++++++++++++++\n",len);
        for(int i = 0; i < len; i++)
        {
            BLE_INFO("%02x",decrpyt_recv_data[i]);
        }
        BLE_INFO("\n");
        free(plaintext);
        return decrpyt_recv_data;
    }
    return NULL;
    
}

#endif
#if 0
uint8_t * decrypt_blufi_data(uint8_t *blufi_data, int *blufi_data_len) 
{
    if((*blufi_data_len) == 0) return NULL;
    char *raw_data = malloc((*blufi_data_len));
    memset(raw_data,0,(*blufi_data_len));
    memcpy(raw_data,blufi_data,((*blufi_data_len)));

    // 加密处理
    char *out_hex = NULL;
    char *tag_hex = NULL;
    char *plaintext = NULL;
    BLE_INFO("=====================原始明文len:%d=================================\n",(*blufi_data_len));
    BLE_INFO("%s\n",raw_data);
    
    aes256_gcm_encrypt(((const char *)raw_data),key, iv1,(const char *)aad,strlen(aad),(*blufi_data_len),&out_hex,&tag_hex);
    int len = aes256_gcm_decrypt((const char *)out_hex,strlen(out_hex), key, iv1, aad, (const char *)tag_hex, &plaintext);
    BLE_INFO("=====================解密明文 len:%d=================================\n",len);
    BLE_INFO("%s\n",plaintext);
    if(plaintext) free(plaintext);
    if(out_hex) free(out_hex);
    if(tag_hex) free(tag_hex);
    return NULL;
}
#endif 
/*
 * 数据通信
 * 给客户端上发加密数据
 * @param blufi_data blufi 数据
 * @param blufi_data_len blufi 数据长度
*/
uint8_t *encrypted_blufi_data(uint8_t *blufi_data, int *blufi_data_len)
{
    if(sharekey == NULL) return NULL;
    int raw_len = *blufi_data_len;
    BLE_INFO("BLE =========send_data_start:%d=============\n",raw_len);
    for(int i = 0; i < raw_len; i++)
    {
        BLE_INFO("%02x",blufi_data[i]);
    }
    BLE_INFO("\n");
    BLE_INFO("BLE =========send_data_end:%d=============\n",raw_len);
    // 加密处理
    char *out_hex = NULL;
    char *tag_hex = NULL;
    // unsigned char iv[GCM_IV_LEN];
    // if (RAND_bytes(iv, sizeof(iv)) != 1) {
    //     BLE_INFO("=================iv create error=======================\n");
    // }
    int len = aes256_gcm_encrypt(((const char *)blufi_data),(const unsigned char *)sharekey->share_key,(const char *)aad,strlen(aad),raw_len,&out_hex,&tag_hex);
    BLE_INFO("out_hex %s out_len:%d",out_hex,strlen(out_hex));
    BLE_INFO("tag_hex %s tag_len:%d",tag_hex,strlen(tag_hex));
    if (len <= 0)
        return NULL;
    // 构造协议头
    size_t header_size = sizeof(EncryptedDataHeader);
    size_t total_size = header_size + strlen(out_hex) + strlen(tag_hex);
    EncryptedDataHeader *header = malloc(total_size);
    memset(header,0,total_size);
    header->data_len = strlen(out_hex);  // 网络字节序
    header->tag_len = strlen(tag_hex);   // 固定标签长度
    // 拷贝加密数据
    size_t offset = 0;
    memcpy(header->data + offset, out_hex, header->data_len);
    offset += header->data_len;
    memcpy(header->data + offset, tag_hex, header->tag_len);
    offset += header->tag_len;
    
    BLE_INFO("\nBLE =========send_data_encrypt_start:%ld=============\n",total_size);
    for(int i = 0; i < total_size; i++)
    {
        BLE_INFO("%02x",((char *)header)[i]);
    }
    BLE_INFO("\n");
    *blufi_data_len = total_size;
    free(out_hex);
    free(tag_hex);
    return (uint8_t *)header;
}
