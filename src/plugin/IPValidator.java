package plugin;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;

public class IPValidator {
  
  //bit length of address
  private static short ADDR_LENGTH =  32;
  private static String MASK_SEPARATOR = "/";
  private static String LINE_COMMENT = "#";
  
  private List<BlacklistEntry> ipBlacklist;
  
  class BlacklistEntry {
    long ipAddress;
    short relevantBits; 
    
    public String toString(){
      return Long.toHexString(ipAddress) + "/" + relevantBits;
    }
  }
  
  public IPValidator(String fileName) throws IOException{
    populateBlacklistFromFile(fileName);
  }
  
  public IPValidator(List<String> entries){
    populateBlacklist(entries);
  }
  
  private void populateBlacklistFromFile(String fileName) throws IOException{
    
    File blacklistFile = new File(fileName);
  
    populateBlacklist(FileUtils.readLines(blacklistFile));//unchecked ok
    
  }
  
  private void populateBlacklist(List<String> entries){
    
    ipBlacklist = new ArrayList<BlacklistEntry>();
    for(String line : entries){
      //remove comments and trim
      int indexOfComment = StringUtils.indexOf(line, LINE_COMMENT);
      if(indexOfComment != StringUtils.INDEX_NOT_FOUND){
        line = StringUtils.substring(line, 0, indexOfComment);
      }
      line = StringUtils.trim(line);
      //is it still a line?
      if(StringUtils.isBlank(line)) continue;
      
      String[] ipAndMask = StringUtils.split(line, MASK_SEPARATOR);
      if(ipAndMask.length < 1 || ipAndMask.length > 2){
        //ToDo: throw something
        return; 
      }
      
      String ipAddress = null;
      String relevantBitNbr = null;
      
      BlacklistEntry entry = new BlacklistEntry();
      
      ipAddress = ipAndMask[0];
      
      entry.ipAddress = getAddressFromIpV4(ipAddress);
      
      if(ipAndMask.length == 2){
        relevantBitNbr = ipAndMask[1];
        entry.relevantBits = Short.parseShort(relevantBitNbr);
      }
      else {
        entry.relevantBits = ADDR_LENGTH;
      }
      
      ipBlacklist.add(entry);
      
    }
  }
  
  final long getAddressFromIpV4(String ip) {
    if (ip == null) return 0;
    int length = ip.length();
    long result = 0;
    short blockNumber = 0;
    long block = 0;
    for (int i = 0; i < length; i++) {
      char c = ip.charAt(i);
      if (c == '.') {
        result += block << ((3 - blockNumber) * 8);
        blockNumber++;
        block = 0;
      } else {
        block = block * 10 + c - '0';
      }
    }
    result += block << ((3 - blockNumber) * 8);
    return result;
  }

  public boolean validateIPAddress(String address){
    return validateIPAddress(getAddressFromIpV4(address));
  }
  
  /**
   * 
   * @return <code>false</code> if exists in blacklist
   */
  public boolean validateIPAddress(long address){
    for(BlacklistEntry entry : ipBlacklist){
      if(addressMatches(address, entry)) return false;
    }
    return true;
  }
  
  private boolean addressMatches(long addressToMatch, BlacklistEntry entry){
    //xor them
    long match = addressToMatch ^ entry.ipAddress;
    //shift so only relevant bits remain
    match = match >> (ADDR_LENGTH - entry.relevantBits);
    return match == 0;
  }
  
  
  
}
