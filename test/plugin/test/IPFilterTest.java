package plugin.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;

import org.junit.Test;

import plugin.IPValidator;

public class IPFilterTest {
 
  
  @Test
  public void testValidateIPAddress() {
    
    ArrayList<String> blacklist = new ArrayList<String>();
    
    blacklist.add("63.245.208.0/20");//208-> 1101 0000
   // blacklist.add("63.245.222.0/24");
    blacklist.add("72.26.221.66");
    blacklist.add("72.26.221.67");
    
    IPValidator ipFilter = new IPValidator(blacklist);
    
    assertTrue(ipFilter.validateIPAddress("63.245.192.26")); //192-> 1100 0000 (no match)
    assertFalse(ipFilter.validateIPAddress("63.245.212.26"));//212-> 1101 0100 (match)
    assertFalse(ipFilter.validateIPAddress("72.26.221.66")); //straight match

  }
  
  @Test
  public void testValidateIPAddressFromFile() throws IOException {
 
    IPValidator ipFilter;
    ipFilter = new IPValidator("blacklist.txt");

    
    assertTrue(ipFilter.validateIPAddress("63.245.192.26")); //192-> 1100 0000 (no match)
    assertFalse(ipFilter.validateIPAddress("63.245.212.26"));//212-> 1101 0100 (match)
    assertFalse(ipFilter.validateIPAddress("72.26.221.66")); //straight match
    
  }

}
