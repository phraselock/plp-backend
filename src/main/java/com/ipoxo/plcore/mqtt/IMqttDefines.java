package com.ipoxo.plcore.mqtt;

public interface IMqttDefines
{
  int KEEP_ALIVE          = 0x3C;  /* 60 Sec. */
  int AND_PING_TIME       = (45);
  int IOS_PING_TIME       = (45);
  int WIN_PING_TIME       = (45 * 1000);
  char PLP_QOS             = (0x00);

}
