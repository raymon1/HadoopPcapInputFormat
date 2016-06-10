package hadoop.pcap.io;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.Iterator;

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

    private LongWritable key = new LongWritable();
    private Text value ;//= new Text();

    long packetCount = 0;
    long start, end, length,index;
    JobConf jconf;

    public PcapRecordReader(long start, long length, FSDataInputStream baseStream, DataInputStream stream, JobConf jconf) throws IOException {
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
        if(index >=end )
                return false;
        key.set(packetCount++);
        k.set(packetCount);

        // big endian    
        // baseStream.seek(index+12);
        // int packet_length = baseStream.readInt();

        // little endian
        byte[] buffer = new byte[4];
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        baseStream.read(index + 12, buffer, 0, 4);
        byteBuffer = ByteBuffer.wrap(buffer);
        int packet_length = byteBuffer.order(ByteOrder.LITTLE_ENDIAN).getInt();
        //

        byte[] packet_buf = new byte[packet_length + 16 ];
        baseStream.read(index, packet_buf, 0, packet_length + 16);
       
        index = index + packet_length + 16;
 
        String s= parsePacket(packet_buf) + "#" + Integer.toString(packet_length);

        value = new Text(s);
        v.set(value);
        return true;
    }

    public String parsePacket(byte [] buf)
    {
        String result = "";
        //time
        //big endian
        // long seconds1 = toSeconds(new byte[]{buf[0], buf[1], buf[2], buf[3]}) ;
        // long microseconds = toSeconds(new byte[]{buf[4], buf[5], buf[6], buf[7]}) / 1000000;   
        
        //little Endian
        long seconds1 = toInt(new byte[]{buf[3], buf[2], buf[1], buf[0]}) ;
        long microseconds =  toInt(new byte[]{buf[7], buf[6], buf[5], buf[4]});
        seconds1 = seconds1 + microseconds / 1000000;
        String seconds = Long.toString(seconds1);

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

        String sourcePort ="-";
        String destPort ="-";                                                                      
        offset = ihl*4 + 16 + 14;
        if(protocol.equals("6") || protocol.equals("17"))
        {
            long x = toInt( new byte[]{(byte)0,(byte)0,buf[offset], buf[offset+1]});//((byte)0,(byte)0,buf[offset], buf[offset+1]) ;
            sourcePort = Long.toString(x);
            x = toInt( new byte[]{(byte)0, (byte)0, buf[offset+2], buf[offset+3]});
            destPort = Long.toString(x);
        }
        
        return sourceIP+"#"+destIP+"#"+protocol+"#"+sourcePort+"#"+destPort+"#"+seconds+"#";
    }

    // public long toInt(byte x1, byte x2, byte x3, byte x4)
    // {
    //     return ((long)x1<<24 | (long) x2<<16 | (long) x3<<8 | (long)x4) & 0xFFFF;
    // }

    public long toInt(byte[] x)
    {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer = ByteBuffer.wrap(x);
        return byteBuffer.order(ByteOrder.BIG_ENDIAN).getInt() & 0xFFFF;
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