package com.ipoxo.plcore.mqtt;

public class MqttConnectProxy
{
  
  private IMqttDelegate mParentMqttDelegate;
  
  void setMqttParentDelegate (IMqttDelegate parentMqttDelegate)
  {
    mParentMqttDelegate = parentMqttDelegate;
  }
  
  public void mqttConnectionEstablished()
  {
    mParentMqttDelegate.mqttConnectionEstablished();
  }
  public void mqttSubscribtionComplet(short  mid){
    mParentMqttDelegate.mqttSubscribtionComplet(mid);
  }
  public void mqttConnectionError(long error, String message) {
    mParentMqttDelegate.mqttConnectionError(error, message);
  }
  public void mqttMessagePublished(){
    mParentMqttDelegate.mqttMessagePublished();
  }
  public void mqttMessagePublishedComplet(short  mid){
    mParentMqttDelegate.mqttMessagePublishedComplet(mid);
  }
  public void mqttSendAutoResponse(byte[] data){
    mParentMqttDelegate.mqttSendAutoResponse(data);
  }
  public void mqttReceivePayload(byte[] topic, byte[] data, short mid){
    mParentMqttDelegate.mqttReceivePayload(topic,data,mid);
  }
  
}
