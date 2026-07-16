package com.ipoxo.plcore.mqtt;

public class MqttWrp
{
  static {
    System.loadLibrary("pllibcpp");
  }
  
  /* Links to native PhraseLock Instance */
  public native void setMqttDelegate(Object mqttDelegate);
  
  public native byte[] createMQTTConnectPacket(String clientId,
                                               String username,
                                               String password);
  
  public native byte[] createMqttConnectPacketLWT(String clientId,
                                                  String username,
                                                  String password,
                                                  char willQoS,
                                                  Boolean willRetain,
                                                  String willTopic,
                                                  String willMessage);
  
  public native byte[] createMQTTPINGPacket();
  
  public native byte[] createMQTTDisconnectPacket();
  
  public native byte[] createMQTTSubscribePacket(char qos,
                                                 short packetId,
                                                 String  topic);
  
  public native byte[] createMQTTUnSubscribePacket(char qos,
                                                   short packetId,
                                                   String topic);
  
  public native byte[] createMQTTPublishPacket(char qos,
                                               short packetId,
                                               String topic,
                                               byte[] msgData);
  
  public native byte[] createMQTTPubAckPacket(short packetId);
  
  public native int parseAndCreateMQTTResponse(byte[] response);
  
}
