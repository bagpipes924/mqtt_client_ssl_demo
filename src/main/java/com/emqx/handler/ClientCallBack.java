package com.emqx.handler;

import org.eclipse.paho.mqttv5.client.IMqttToken;
import org.eclipse.paho.mqttv5.client.MqttCallback;
import org.eclipse.paho.mqttv5.client.MqttDisconnectResponse;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;
import org.eclipse.paho.mqttv5.common.packet.MqttProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ClientCallBack implements MqttCallback {
	private final static Logger logger = LoggerFactory.getLogger(ClientCallBack.class);

	public void disconnected(MqttDisconnectResponse disconnectResponse) {
		// TODO Auto-generated method stub
		
	}

	public void mqttErrorOccurred(MqttException exception) {
		logger.error("连接断开，准备重连:"+exception.getMessage());
		
	}

	public void messageArrived(String topic, MqttMessage message) throws Exception {
		// TODO Auto-generated method stub
		logger.info("topic: "+topic+" ,接收消息Qos: " + message.getQos()+"接收消息内容:" + new String(message.getPayload()));
		
	}

	public void deliveryComplete(IMqttToken token) {
		// TODO Auto-generated method stub
		
	}

	public void connectComplete(boolean reconnect, String serverURI) {
		// TODO Auto-generated method stub
		
	}

	public void authPacketArrived(int reasonCode, MqttProperties properties) {
		// TODO Auto-generated method stub
		
	}

}
