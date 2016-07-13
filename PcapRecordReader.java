//package hadoop.pcap.io;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Iterator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.hadoop.fs.Seekable;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.util.StringUtils;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.InputSplit;
import org.apache.hadoop.mapred.TaskAttemptContext;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.JobConf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;


public class PcapRecordReader implements RecordReader<LongWritable, Text> {
    FSDataInputStream baseStream;
    DataInputStream stream;
    TaskAttemptContext context;
    public static final Log LOG = LogFactory.getLog(PcapRecordReader.class);

    private LongWritable key = new LongWritable();
    private Text value ;//= new Text();

    long packetCount = 0;
    long start, end, length,index;
    JobConf jconf;

    public PcapRecordReader(long start, long length, FSDataInputStream baseStream, DataInputStream stream, JobConf jconf) throws IOException {
        LOG.info("initialized ");

        this.baseStream = baseStream;
        this.stream = stream;
        this.jconf = jconf;
        this.start = start;
        this.length = length;
        this.index = start;
        this.end = start + length;
    }

    //@Override
    public void initialize(InputSplit inputSplit, TaskAttemptContext taskAttemptContext) throws IOException, InterruptedException {}

    //@Override
    public synchronized void close() throws IOException {
        stream.close();
    }

    //@Override
    public synchronized boolean next(LongWritable k, Text v) throws IOException {
        //LOG.info("entered next "+index);

        if(index >= end)
                return false;
        key.set(packetCount++);
        k.set(packetCount);

        // big endian reading of packet record length   
        baseStream.seek(index+8);
        long packet_length = ((long) baseStream.readInt()) & 0xFFFFFFFFL;

        int read_packet_size = 15*4 + 14 + 10  ; //15 max ihl value, 16 pcap packet header, 14 ethernet, 20 extra for safety

        if(packet_length < read_packet_size  && packet_length > 0)
            read_packet_size = (int)packet_length;
        //reading packet record bytes 
        byte[] packet_buf = new byte[read_packet_size + 16 ];
        baseStream.read(index, packet_buf, 0, read_packet_size + 16);
        
        //updating index to point at the start of the next record
        index = index + packet_length + 16;
        
        //parse packet size into strings and set it as the value of this mapper record
        String s= parsePacket(packet_buf) + "#" + Long.toString(packet_length);
        value = new Text(s);
        v.set(value);
        return true;
    }

    //parse the packet raw bytes into string data 
    //This function can be replaced by a packet parsing class or a different function to parse different fields
    public String parsePacket(byte [] buf)
    {
        String result = "";
        //time
        //big endian
        byte[] y = new byte[]{0, buf[0], buf[1], buf[2], buf[3]};
        long seconds1 = toInt(y) ;
        y = new byte[]{0, buf[4], buf[5], buf[6], buf[7]};
        long microseconds1 = toInt(y) ;// / 1000000;   
        
        //little Endian
        // long seconds1 = toInt(new byte[]{buf[3], buf[2], buf[1], buf[0]}) ;
        // long microseconds =  toInt(new byte[]{buf[7], buf[6], buf[5], buf[4]});
        String seconds = Long.toString(seconds1);
        String microseconds = Long.toString(microseconds1);
        int offset = 16 + 14; // 16 is pcappacket header length, 14 is ethernet header length
        int ihl = (int)buf[offset] & 15; //IHL is the second half byte
        
        offset = offset + 9; //39
        String protocol = Integer.toString((int)buf[offset] & 0xFF);
        
        offset =  offset + 3; //42
        String sourceIP = Integer.toString((int)buf[offset] & 0xFF) + "."
                        + Integer.toString((int)buf[offset+1] & 0xFF) + "." 
                        + Integer.toString((int)buf[offset+2] & 0xFF) + "."
                        + Integer.toString((int)buf[offset+3] & 0xFF);
        String destIP = Integer.toString((int)buf[offset+4] & 0xFF) + "."
                        + Integer.toString((int)buf[offset+5] & 0xFF) + "."
                        + Integer.toString((int)buf[offset+6] & 0xFF) + "."
                        + Integer.toString((int)buf[offset+7] & 0xFF);

        String sourcePort ="0";
        String destPort ="0";                                                                      
        offset = ihl*4 + 16 + 14;
        if((protocol.equals("6") || protocol.equals("17")) && offset + 3 < buf.length )
        {
            long x = toInt( new byte[]{(byte)0,(byte)0,buf[offset], buf[offset+1]});//((byte)0,(byte)0,buf[offset], buf[offset+1]) ;
            sourcePort = Long.toString(x);
            x = toInt( new byte[]{(byte)0, (byte)0, buf[offset+2], buf[offset+3]});
            destPort = Long.toString(x);
        }
        
        return sourceIP+"#"+destIP+"#"+protocol+"#"+sourcePort+"#"+destPort+"#"+seconds+"#"+microseconds;
    }

    public long toInt(byte[] x)
    {
        long ret = 0;
        for (int i=0; i<x.length; i++) {
            ret <<= 8;
            ret = ret | (((long)x[i]) & 0xFFL);
        }
        return ret; 
    }

    //@Override
    public Text getCurrentValue() {
        return value;
    }

    //@Override
    public LongWritable getCurrentKey() {
        return key;
    }

    @Override
    public long getPos() throws IOException {
        return baseStream.getPos();
    }

    @Override
    public float getProgress() throws IOException {
        if (start == end)
            return 0;
        return Math.min(1.0f, (getPos() - start) / (float)(end - start));
    }

    @Override
    public LongWritable createKey() {
        return new LongWritable();
     }
      
      /**
       * Create an object of the appropriate type to be used as a value.
       * 
       * @return a new value object.
       */
    @Override
    public  Text createValue() {
        return new Text();
      }
    
     
     
}