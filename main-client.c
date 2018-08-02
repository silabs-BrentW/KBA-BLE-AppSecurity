/***********************************************************************************************//**
 * \file   main.c
 * \brief  Silicon Labs Empty Example Project
 *
 * This example demonstrates the bare minimum needed for a Blue Gecko C application
 * that allows Over-the-Air Device Firmware Upgrading (OTA DFU). The application
 * starts advertising after boot and restarts advertising after a connection is closed.
 ***************************************************************************************************
 * <b> (C) Copyright 2016 Silicon Labs, http://www.silabs.com</b>
 ***************************************************************************************************
 * This file is licensed under the Silabs License Agreement. See the file
 * "Silabs_License_Agreement.txt" for details. Before using this software for
 * any purpose, you must agree to the terms of that agreement.
 **************************************************************************************************/

/* Board headers */
#include "init_mcu.h"
#include "init_board.h"
#include "init_app.h"
#include "ble-configuration.h"
#include "board_features.h"

/* Bluetooth stack headers */
#include "bg_types.h"
#include "native_gecko.h"
#include "gatt_db.h"
//#include "aat.h"
#include "aes.h"
/* Libraries containing default Gecko configuration values */
#include "em_emu.h"
#include "em_cmu.h"

//#include "infrastructure.h"
/* Device initialization header */
#if defined(HAL_CONFIG)
#include "bsphalconfig.h"
#else
#include "bspconfig.h"
#endif
//#include "bsp.h"
#include <stdio.h>
#include <string.h>
#include "encrypt.h"
/***********************************************************************************************//**
 * @addtogroup Application
 * @{
 **************************************************************************************************/
//#define PRINT_UUID 1
/***********************************************************************************************//**
 * @addtogroup app
 * @{
 **************************************************************************************************/

#ifndef MAX_CONNECTIONS
#define MAX_CONNECTIONS 4
#endif
uint8_t bluetooth_stack_heap[DEFAULT_BLUETOOTH_HEAP(MAX_CONNECTIONS)];


#define AES_BLOCK_SIZE        16

/* Gecko configuration parameters (see gecko_configuration.h) */
static const gecko_configuration_t config = {
  .config_flags=0,
  .sleep.flags=SLEEP_FLAGS_DEEP_SLEEP_ENABLE,
  .bluetooth.max_connections=MAX_CONNECTIONS,
  .bluetooth.heap=bluetooth_stack_heap,
  .bluetooth.heap_size=sizeof(bluetooth_stack_heap),
  .bluetooth.sleep_clock_accuracy = 100, // ppm
  .gattdb=&bg_gattdb_data,
  .ota.flags=0,
  .ota.device_name_len=3,
  .ota.device_name_ptr="OTA",

  #ifdef USE_PA
  .pa.config_enable = 1,
  .pa.input = GECKO_RADIO_PA_INPUT_VBAT,
  #endif

};

/* Flag for indicating DFU Reset must be performed */
uint8_t boot_to_dfu = 0;


/*
 * Encrypted data service
 * 8dcd0dfe-0faf-499a-9993-4010c20db5da
 *
 * */
static const uint8 silabs_appsec_svc_uuid[16] = {0x8d,0xcd,0x0d,0xfe,0x0f,0xaf,0x49,0x9a,0x99,0x93,0x40,0x10,0xc2,0x0d,0xb5,0xda};
static const uint8 silabs_appsec_characteristic_rd_uuid[16] = {0x55,0x54,0x47,0x22,0xcd,0x87,0x45,0x9e,0xae,0x1b,0x4c,0x05,0x14,0xcb,0x2f,0xd5};
static const uint8 silabs_appsec_characteristic_wr_uuid[16] = {0x68,0x45,0x5b,0x5a,0x1b,0xd4,0x4d,0xb5,0xa4,0xad,0xb9,0xc9,0xfc,0x20,0x6b,0x24};
/*

  check_uuid()
   
  Description : compares two UUIDs which are in opposite order
  returns : true 


*/


enum {idle, connected, service_discovered, characteristic_discovered, notifications_active, characteristic_read, done} gatt_state;


void print_uuid16(uint8* uuid){
  
  printf("UUID: ");
  for(int i=0;i<16;i++){
    printf("%x ", *(uuid+i));
  }
  printf("\r\n");
  
}

//#define PRINT_UUID 1
/**************************************************************
 *
 *  function: check_uuid
 *  Description: helper function to compare two UUIDs
 *
 *************************************************************/
bool check_uuid(uint8 const *uuid1, uint8 *uuid2, uint8 len){

    bool match = false;
    int i;


#ifdef PRINT_UUID
    printf("comparing \r\n");
    print_uuid16((uint8 *)uuid1);
    printf("against \r\n");
    print_uuid16(uuid2);
#endif
    /* uuid is in reverse order in advertising packet*/
    for(i= 0;i<len;i++){
	if(*(uuid2 + (len - i - 1)) != *(uuid1+i)){
	  return match;
	}

    }
    match = true;
    return match;
}

/**************************************************************
 *
 *  function: print_block
 *  Description: helper function to print out a block
 *                of hexadecimal data
 *
 *************************************************************/

void print_block(uint8 *block, size_t size){
	 for(int i=0;i<size;i++){
		 printf("%X", *block++);
	 }

	 printf("\n");
 }

/**************************************************************
 *
 *  function: reset_IV
 *  Description: helper function to reset the IV
 *
 *************************************************************/

void reset_IV(uint8 * ivToReset){

	memset(ivToReset,0,AES_BLOCK_SIZE);

}


extern mbedtls_aes_context aes_ctx;
/**
 * @brief  Main function
 */
int main(void)
{
    uint8 scan_uuid[16], connection = 0xFF;
    uint16 appsec_characteristic_rd_handle = 0xFF, appsec_characteristic_wr_handle = 0xFF;
    //struct gecko_msg_system_set_tx_power_rsp_t * set_tx_pwr_resp;

    /* AES related data*/
    struct crypto_result ciphertext, received_plaintext;
    uint8_t plainTextToSend[16] = "First message";
    /* need a different initialization vector for each data path*/
    uint8_t iv1[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    		iv2[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uint8_t key[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

#ifdef FEATURE_SPI_FLASH
  /* Put the SPI flash into Deep Power Down mode for those radio boards where it is available */
  MX25_init();
  MX25_DP();
  /* We must disable SPI communication */
  USART_Reset(USART1);

#endif /* FEATURE_SPI_FLASH */

  /* Initialize peripherals */

  mbedtls_aes_init(&aes_ctx);


  initMcu();
   // Initialize board
   initBoard();
   // Initialize application
   initApp();


  RETARGET_SerialInit();

  /* Initialize stack */
  gecko_init(&config);

  while (1) {
    /* Event pointer for handling events */
    struct gecko_cmd_packet* evt;
    
    /* Check for stack event. */
    evt = gecko_wait_event();

    /* Handle events */
    switch (BGLIB_MSG_ID(evt->header)) {

      /* This boot event is generated when the system boots up after reset.
       * Here the system is set to start advertising immediately after boot procedure. */
      case gecko_evt_system_boot_id:

        /* set state machine into idle state*/
        gatt_state = idle;
        
        /* set transmit power to the maximum +10.5 dBm*/
        //set_tx_pwr_resp =
        gecko_cmd_system_set_tx_power(105);
    	printf("Application security client example booted\r\n");
        
        /* set preferred connection parameters. Use a long timeout to allow for more retries at the edge of range
         *
         * 700 *1.25 ms = 875, 760 * 1.25 ms = 950 ms, latency = 1, timeout = 3200*10ms = 32 s
         * */
        gecko_cmd_le_gap_set_conn_parameters(700,760,1,3200);
    	
        /* 200 ms scan window min/max, passive scan*/
    	gecko_cmd_le_gap_set_scan_parameters(320,320,0);
    	/* start listening for devices to connect to */
    	gecko_cmd_le_gap_discover(le_gap_discover_generic);
        break;

      /* endpoint status event handler */  
      case gecko_evt_endpoint_status_id:
    	  /* endpoints not used in this application*/
    	  break;

      /* GAP scan response event handler */    
      case gecko_evt_le_gap_scan_response_id:
      {
         bd_addr slave_address =  evt->data.evt_le_gap_scan_response.address;
         int index = 0;
    	 printf("scan response, packet type %d\n", evt->data.evt_le_gap_scan_response.packet_type);

    	 while(index < evt->data.evt_le_gap_scan_response.data.len){
    		 /* is this PDU the complete list of 128 bit services?*/
    		 if(evt->data.evt_le_gap_scan_response.data.data[index+1] == 0x07){
    	        memcpy(scan_uuid,&evt->data.evt_le_gap_scan_response.data.data[index+2],16);
    	        break;
    		 }
    		 /* check the next one*/
    		 else {
    			 index = index + evt->data.evt_le_gap_scan_response.data.data[index] + 1;
    		 }
    	 }
         /* check to see if advertising device is advertising the expected service.*/
         if( evt->data.evt_le_gap_scan_response.packet_type == 0 &&
             check_uuid(silabs_appsec_svc_uuid,scan_uuid, 16) == true){
                     
               //  printf("found device advertising service uuid %16X\r\n", evt->data.evt_le_gap_scan_response.data.data[5]);
               printf("connecting to remote GATT server with address %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\r\n",
            		   slave_address.addr[5],slave_address.addr[4],	slave_address.addr[3],
					   slave_address.addr[2],slave_address.addr[1], slave_address.addr[0]);

               /* stop scanning for now */
               gecko_cmd_le_gap_end_procedure();

               /* and connect to the advertising device*/
               gecko_cmd_le_gap_open(evt->data.evt_le_gap_scan_response.address ,le_gap_address_type_public);
              }
      }
      break;
              
      /* connection opened event handler */        
      case gecko_evt_le_connection_opened_id:
    	  printf("connection opened\r\n");
          gatt_state = connected;
    	  connection = evt->data.evt_le_connection_opened.connection;
     	  break;
          
     /* GATT MTU exchanged event handler */
     case gecko_evt_gatt_mtu_exchanged_id:
    	//Informative event about the MTU size currently in use
        //printf("mtu exchanged\r\n");
    	break;
      
      /* connection parameters event handler */
      case gecko_evt_le_connection_parameters_id:
        {
          /* if we are in the connected state, ie just connected, look for included services */
          if(gatt_state==connected){
            gecko_cmd_gatt_discover_primary_services(connection);
          }
        }
    	break;

      /* GATT service event handler */    
      case gecko_evt_gatt_service_id:
        {
          uint32 service = evt->data.evt_gatt_service.service;
          uint8 connection = evt->data.evt_gatt_service.connection;
          uint8 *serviceUuid = evt->data.evt_gatt_service.uuid.data;
          
          /* update the state machine to indicate that the service has been found*/
          gatt_state = service_discovered;
          //printf("service discovered\n");
          
          /* check to see if this is the LE range test service*/
          if(evt->data.evt_gatt_service.uuid.len == 16){
            if(check_uuid(silabs_appsec_svc_uuid,serviceUuid,16)){
                //printf("found AppSec service\n");
                gecko_cmd_gatt_discover_characteristics(connection, service);
            }
          }
        }
      break;
      
    /* GATT characteristic event handler */  
    case gecko_evt_gatt_characteristic_id:
      {
        //uint8 connection = evt->data.evt_gatt_characteristic.connection;
        uint8 len = evt->data.evt_gatt_characteristic.uuid.len;
        uint8 *uuid = evt->data.evt_gatt_characteristic.uuid.data;
        uint16 _characteristic = evt->data.evt_gatt_characteristic.characteristic;
        
        //printf("characteristic discovered\n");

        /* determine which characteristic was discovered and save characteristic handles for future use */
        if(check_uuid(silabs_appsec_characteristic_rd_uuid,uuid, len)){
          appsec_characteristic_rd_handle = _characteristic;
          gatt_state = characteristic_discovered;
          //  printf("gatt write response %d\n", gatt_write_response->result);
        }
        else if(check_uuid(silabs_appsec_characteristic_wr_uuid, uuid, len)){
        	appsec_characteristic_wr_handle = _characteristic;
            ciphertext = handle_encryption_cbc(plainTextToSend, key, iv2, MBEDTLS_AES_ENCRYPT);
            //uncomment the following lines to print out the encrypted data
        	//printf("data encrypted as : ");
        	//print_block(ciphertext.output,AES_BLOCK_SIZE);
        }
      }
      break;



    /* characteristic value event handler*/ 
    case gecko_evt_gatt_characteristic_value_id:
      {
        uint8 rxData[16];

        memcpy(rxData,evt->data.evt_gatt_characteristic_value.value.data,16);

        /* check to see if the data received is on the test data characteristic*/
        if(evt->data.evt_gatt_characteristic_value.characteristic==appsec_characteristic_rd_handle){
            /* print out the received data*/
            //printf("received encrypted data : ");
            //print_block(evt->data.evt_gatt_server_user_write_request.value.data, 16);

            /* decrypt the received data*/
            received_plaintext = handle_encryption_cbc(rxData, key, iv1, MBEDTLS_AES_DECRYPT);
            //uncomment following lines to see IV used
            //printf("encrypted data decoded with iv ");
            //print_block(iv1,16);

            /* decoded plain text should be in ASCII*/
            //uncomment following line to print output as hex insteadof ASCII
            // print_block(received_plaintext.output, 16);
            printf("Decoded as: %s\n",received_plaintext.output);
        }
      }
      break;

      /* gatt procedure completed event handler */
      case gecko_evt_gatt_procedure_completed_id:

         /* if the state is characteristic_discovered, then we have the handle for the characteristic but
         have not yet subscribed to notifications*/
         if(gatt_state == characteristic_discovered){
      	 // read the encrypted characteristic
           gecko_cmd_gatt_read_characteristic_value(connection, appsec_characteristic_rd_handle);
           gatt_state = characteristic_read;
         }
         else if(gatt_state == characteristic_read){
        	 gecko_cmd_gatt_write_characteristic_value(connection, appsec_characteristic_wr_handle, 16, ciphertext.output);
        	 gatt_state = done;

         }
         break;

      /*  PHY status event handler */
      case gecko_evt_le_connection_phy_status_id:
    	 
        /* report the current PHY*/
        printf("now using PHY # %d\r\n", evt->data.evt_le_connection_phy_status.phy);
    	break;

      /* connection closed event handler */  
      case gecko_evt_le_connection_closed_id:
	
        /* update state machine for future connections*/
        gatt_state = idle;
        /*
         * reset the intialization vectors to zero to remain in sync with server
         *
         * */
        reset_IV(iv1);
        reset_IV(iv2);
        
        /* TODO consider reset IVs here*/

        /* restart the discovery process*/
        printf("connection closed, restarting discovery\n");
        gecko_cmd_le_gap_discover(le_gap_discover_generic);
        
        /* Check if need to boot to dfu mode */
        if (boot_to_dfu) {
          /* Enter to DFU OTA mode */
          gecko_cmd_system_reset(2);
        }
        else { /* restart discovery on disconnect */
          gecko_cmd_le_gap_discover(le_gap_discover_generic);
        }
        break;

            /* Events related to OTA upgrading
      ----------------------------------------------------------------------------- */

      /* Check if the user-type OTA Control Characteristic was written.
       * If ota_control was written, boot the device into Device Firmware Upgrade (DFU) mode. */
      case gecko_evt_gatt_server_user_write_request_id:
      
        if(evt->data.evt_gatt_server_user_write_request.characteristic==gattdb_ota_control) {
          /* Set flag to enter to OTA mode */
          boot_to_dfu = 1; 
          /* Send response to Write Request */
          gecko_cmd_gatt_server_send_user_write_response(evt->data.evt_gatt_server_user_write_request.connection, gattdb_ota_control, bg_err_success);
         
          /* Close connection to enter to DFU OTA mode */        
          gecko_cmd_endpoint_close(evt->data.evt_gatt_server_user_write_request.connection);
        }

        break;

      /* default handler, check for any unhandled events */  
      default:
    	 // printf("unhandled event 0x%X\r\n", BGLIB_MSG_ID(evt->header));
        break;
    }
  }
  return -1;
}


/** @} (end addtogroup app) */
/** @} (end addtogroup Application) */
