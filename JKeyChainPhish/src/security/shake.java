package security;

import java.awt.*;

public class shake {

  private final static int VIBRATION_LENGTH = 2;
  private final static int VIBRATION_DISTANCE = 10;
  private final static int VIBRATION_TIME = 50;
  
  private shake() { 
  }
  
  public static void vibrate(Frame frame) { 
    try { 
      final int originalX = frame.getLocationOnScreen().x; 
      final int originalY = frame.getLocationOnScreen().y; 
      for(int i = 0; i < VIBRATION_LENGTH; i++) { 
        /*Thread.sleep(VIBRATION_TIME); 
        frame.setLocation(originalX, originalY + VIBRATION_DISTANCE); 
        Thread.sleep(VIBRATION_TIME);
        frame.setLocation(originalX, originalY - VIBRATION_DISTANCE);*/
        Thread.sleep(VIBRATION_TIME); 
        frame.setLocation(originalX + VIBRATION_DISTANCE, originalY);
        Thread.sleep(VIBRATION_TIME); 
        frame.setLocation(originalX, originalY); 
      } 
    } 
    catch (Exception err) { 
      err.printStackTrace(); 
    }
  }
}
  