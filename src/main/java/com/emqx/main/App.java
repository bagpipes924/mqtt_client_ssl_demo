package com.emqx.main;


import org.eclipse.paho.mqttv5.client.IMqttToken;
import org.eclipse.paho.mqttv5.client.MqttActionListener;
import org.eclipse.paho.mqttv5.client.MqttAsyncClient;
import org.eclipse.paho.mqttv5.client.MqttClient;
import org.eclipse.paho.mqttv5.client.MqttConnectionOptions;
import org.eclipse.paho.mqttv5.client.persist.MemoryPersistence;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.emqx.handler.ClientCallBack;
import com.emqx.util.SslUtil;


/**
 * Hello world!
 *
 */
public class App {
	private final static Logger logger = LoggerFactory.getLogger(App.class);
	private static boolean ssl=false; //是否认证
	private static String broker =null;
    public static void main( String[] args ) throws Exception{
        String clientid="test";
        //System.setProperty("javax.net.debug", "all");
        String ip="192.168.7.27";
        if(ssl) {
        	broker="ssl://"+ip+":8883";
        }else {
        	broker="tcp://"+ip+":1883";
		}
        MqttConnectionOptions connOpts=getconnOpts();
        //final MqttAsyncClient client=new MqttAsyncClient(broker, clientid, new MemoryPersistence());
        MqttClient client=new MqttClient(broker, clientid, new MemoryPersistence());
        client.setCallback(new ClientCallBack());
        client.connect(connOpts);
        client.subscribe("test/#",1);
        logger.debug("是否启动认证："+ssl);
        logger.info("连接成功："+broker);
        logger.error("测试错误日志");
        /*
        client.connect(connOpts, null, new MqttActionListener() {

			public void onSuccess(IMqttToken asyncActionToken) {
				logger.info("连接成功："+broker);
				try {
					client.subscribe("test/#",1);

				} catch (MqttException e) {
					System.out.println("reason " + e.getReasonCode());
                    System.out.println("msg " + e.getMessage());
                    System.out.println("loc " + e.getLocalizedMessage());
                    System.out.println("cause " + e.getCause());
                    System.out.println("excep " + e);
					e.printStackTrace();
				}
				
			}

			public void onFailure(IMqttToken asyncActionToken, Throwable exception) {
				System.out.println("mqtt 没有连接上:" + exception.getMessage());
				
			}
        	
        });
        */
        
    }
    private static MqttConnectionOptions getconnOpts() throws Exception {
    	String caCrtFile="/Users/bagpipes/Downloads/cert/openssl2/certs/ca.pem";
    	String crtFile="/Users/bagpipes/Downloads/cert/openssl2/certs/client.pem";
    	String keyFile="/Users/bagpipes/Downloads/cert/openssl2/private/client-key.pem";
    	String password="123456";
    	MqttConnectionOptions connOpts = new MqttConnectionOptions();
    	connOpts.setUserName("Username");
    	connOpts.setPassword("password".getBytes());
    	connOpts.setKeepAliveInterval(30);
    	connOpts.setCleanStart(true);
    	connOpts.setConnectionTimeout(60);
    	connOpts.setAutomaticReconnect(true);
    	
    	if(ssl) {
    		connOpts.setHttpsHostnameVerificationEnabled(false); //证书中未包含域名
    		connOpts.setSocketFactory(SslUtil.getSocketFactory(caCrtFile, crtFile, keyFile, password));
    	}
    	return connOpts;
    }
}
