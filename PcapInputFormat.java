//package hadoop.pcap.io;
//import hadoop.pcap.io.PcapRecordReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.ObjectWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileSplit;
import org.apache.hadoop.mapred.InputSplit;
import org.apache.hadoop.mapred.JobContext;
import org.apache.hadoop.mapred.RecordReader;
import org.apache.hadoop.mapred.TaskAttemptContext;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.net.Node;
import org.apache.hadoop.net.NodeBase;
import org.apache.hadoop.util.ReflectionUtils;
import org.apache.hadoop.util.StringUtils;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.BlockLocation;
import org.apache.hadoop.fs.LocatedFileStatus;
import org.apache.hadoop.net.NetworkTopology;
import java.util.concurrent.TimeUnit;
import com.google.common.base.Stopwatch;



public class PcapInputFormat extends FileInputFormat<LongWritable, Text> {
  static final String READER_CLASS_PROPERTY = "hadoop.pcap.io.reader.class";

  public static final Log LOG = LogFactory.getLog(PcapInputFormat.class);

    @Override //create? get?
    public  RecordReader<LongWritable, Text> getRecordReader(InputSplit split,
     JobConf job,
     Reporter reporter) throws IOException {
      reporter.setStatus(split.toString());
      FileSplit fileSplit = (FileSplit)split;
      Path path = fileSplit.getPath();
      LOG.info("Reading PCAP: " + path.toString());
      long start = fileSplit.getStart();
      long length = fileSplit.getLength();
      return initPcapRecordReader(path, start, length, job); //reporter wla job
    }

    public static PcapRecordReader initPcapRecordReader(Path path, long start, long length, JobConf jconf) throws IOException {
        //Configuration conf = cont/ext.getConfiguration();
      FileSystem fs = path.getFileSystem(jconf);
      FSDataInputStream baseStream = fs.open(path);
      DataInputStream stream = baseStream;
      CompressionCodecFactory compressionCodecs = new CompressionCodecFactory(jconf);
      final CompressionCodec codec = compressionCodecs.getCodec(path);
      if (codec != null)
        stream = new DataInputStream(codec.createInputStream(stream));
      return new PcapRecordReader(start, length, baseStream, stream, jconf);
    }

  
    @Override
    public InputSplit[] getSplits(JobConf job, int numSplits)
    throws IOException {
       LOG.info("Entered getSplits");
        
      Stopwatch sw = new Stopwatch().start();
      FileStatus[] files = listStatus(job);

        // Save the number of input files for metrics/loadgen
      job.setLong(NUM_INPUT_FILES, files.length);
        long totalSize = 0;                           // compute total size
        for (FileStatus file: files) {                // check we have valid files
          if (file.isDirectory()) {
            throw new IOException("Not a file: "+ file.getPath());
          }
          totalSize += file.getLen();
        }

        LOG.info("file size is "+totalSize);

        long goalSize = totalSize / (numSplits == 0 ? 1 : numSplits);
        long minSize = Math.max(job.getLong(org.apache.hadoop.mapreduce.lib.input.
          FileInputFormat.SPLIT_MINSIZE, 1), 1);

        // generate splits
        ArrayList<FileSplit> splits = new ArrayList<FileSplit>(numSplits);
        NetworkTopology clusterMap = new NetworkTopology();
        for (FileStatus file: files) {
          Path path = file.getPath();
          long length = file.getLen();
          if (length != 0) {
            FileSystem fs = path.getFileSystem(job);
            BlockLocation[] blkLocations;
            if (file instanceof LocatedFileStatus) {
              blkLocations = ((LocatedFileStatus) file).getBlockLocations();
            } else {
              blkLocations = fs.getFileBlockLocations(file, 0, length);
            }
            if (isSplitable(fs, path)) {
              long blockSize = file.getBlockSize();
              long splitSize = computeSplitSize(goalSize, minSize, blockSize);

              FSDataInputStream in = fs.open(path);

              long bytesRemaining = length;
              long pos = length -bytesRemaining;
              while (((double) bytesRemaining)/splitSize > 1.1 && in.available() > 0) {
                //////////////////////////////                        
                // 24 byte is pcap file general header, and the 9th-12th bytes of every record represent the packet length 
                long start = pos; 
                if(start == 0)
                {
                  pos = 24;
                  start = 24;
                  bytesRemaining -= 24;
                }                        
                long len = 0;
                LOG.info("start of split at: "+pos);

                if(in.available() > 0)
                {
                  //Bigendian reading
                  in.seek(pos + 8);
                  len = ((long) in.readInt()) & 0xFFFFFFFFL;
                  pos += len + 16;
                }

                while(in.available() > 0 )//&& length - pos > 16)
                {
                  //bigendian
                  in.seek(pos + 8);
                  len = ((long) in.readInt()) & 0xFFFFFFFFL;

                  if ((double) pos + len + 16 - start > splitSize * 1.1)
                    break;
                  pos += len + 16;
                }
                /////////////////////////////
                LOG.info("end of split at: "+pos);



                String[][] splitHosts = getSplitHostsAndCachedHosts(blkLocations,
                  start, (pos-start), clusterMap);
                splits.add(makeSplit(path, start, pos-start,
                  splitHosts[0], splitHosts[1]));
                bytesRemaining = bytesRemaining - (pos-start);
              }

              LOG.info("remaining "+bytesRemaining);

              if (bytesRemaining != 0) {
                String[][] splitHosts = getSplitHostsAndCachedHosts(blkLocations, length
                  - bytesRemaining, bytesRemaining, clusterMap);
                splits.add(makeSplit(path, length - bytesRemaining, bytesRemaining,
                  splitHosts[0], splitHosts[1]));
              }
            } else {
              String[][] splitHosts = getSplitHostsAndCachedHosts(blkLocations,0,length,clusterMap);
              splits.add(makeSplit(path, 0, length, splitHosts[0], splitHosts[1]));
            }
          } else { 
            //Create empty hosts array for zero length files
            splits.add(makeSplit(path, 0, length, new String[0]));
          }
        }
        sw.stop();
        if (LOG.isDebugEnabled()) {
          LOG.debug("Total # of splits generated by getSplits: " + splits.size()
            + ", TimeTaken: " + sw.elapsedMillis());
        }
        LOG.info("leaving getSplits()");
        return splits.toArray(new FileSplit[splits.size()]);
      }  

       protected long computeSplitSize(long blockSize, long minSize,
                                  long maxSize) {
          return Math.max(minSize, Math.min(maxSize, blockSize));
      }


      private void sortInDescendingOrder(List<NodeInfo> mylist) {
        Collections.sort(mylist, new Comparator<NodeInfo> () {
          public int compare(NodeInfo obj1, NodeInfo obj2) {

            if (obj1 == null || obj2 == null)
              return -1;

            if (obj1.getValue() == obj2.getValue()) {
              return 0;
            }
            else {
              return ((obj1.getValue() < obj2.getValue()) ? 1 : -1);
            }
          }
        }
        );
      }


      private String[][] getSplitHostsAndCachedHosts(BlockLocation[] blkLocations, 
        long offset, long splitSize, NetworkTopology clusterMap)
      throws IOException {

        int startIndex = getBlockIndex(blkLocations, offset);

        long bytesInThisBlock = blkLocations[startIndex].getOffset() + 
        blkLocations[startIndex].getLength() - offset;

        //If this is the only block, just return
        if (bytesInThisBlock >= splitSize) {
          return new String[][] { blkLocations[startIndex].getHosts(),
            blkLocations[startIndex].getCachedHosts() };
          }

          long bytesInFirstBlock = bytesInThisBlock;
          int index = startIndex + 1;
          splitSize -= bytesInThisBlock;

          while (splitSize > 0) {
            bytesInThisBlock =
            Math.min(splitSize, blkLocations[index++].getLength());
            splitSize -= bytesInThisBlock;
          }

          long bytesInLastBlock = bytesInThisBlock;
          int endIndex = index - 1;

          Map <Node,NodeInfo> hostsMap = new IdentityHashMap<Node,NodeInfo>();
          Map <Node,NodeInfo> racksMap = new IdentityHashMap<Node,NodeInfo>();
          String [] allTopos = new String[0];

        // Build the hierarchy and aggregate the contribution of 
        // bytes at each level. See TestGetSplitHosts.java 

          for (index = startIndex; index <= endIndex; index++) {

          // Establish the bytes in this block
            if (index == startIndex) {
              bytesInThisBlock = bytesInFirstBlock;
            }
            else if (index == endIndex) {
              bytesInThisBlock = bytesInLastBlock;
            }
            else {
              bytesInThisBlock = blkLocations[index].getLength();
            }

            allTopos = blkLocations[index].getTopologyPaths();

          // If no topology information is available, just
          // prefix a fakeRack
            if (allTopos.length == 0) {
              allTopos = fakeRacks(blkLocations, index);
            }

          // NOTE: This code currently works only for one level of
          // hierarchy (rack/host). However, it is relatively easy
          // to extend this to support aggregation at different
          // levels 

            for (String topo: allTopos) {

              Node node, parentNode;
              NodeInfo nodeInfo, parentNodeInfo;

              node = clusterMap.getNode(topo);

              if (node == null) {
                node = new NodeBase(topo);
                clusterMap.add(node);
              }

              nodeInfo = hostsMap.get(node);

              if (nodeInfo == null) {
                nodeInfo = new NodeInfo(node);
                hostsMap.put(node,nodeInfo);
                parentNode = node.getParent();
                parentNodeInfo = racksMap.get(parentNode);
                if (parentNodeInfo == null) {
                  parentNodeInfo = new NodeInfo(parentNode);
                  racksMap.put(parentNode,parentNodeInfo);
                }
                parentNodeInfo.addLeaf(nodeInfo);
              }
              else {
                nodeInfo = hostsMap.get(node);
                parentNode = node.getParent();
                parentNodeInfo = racksMap.get(parentNode);
              }

              nodeInfo.addValue(index, bytesInThisBlock);
              parentNodeInfo.addValue(index, bytesInThisBlock);

          } // for all topos

        } // for all indices

        // We don't yet support cached hosts when bytesInThisBlock > splitSize
        return new String[][] { identifyHosts(allTopos.length, racksMap),
          new String[0]};
        }

        private String[] identifyHosts(int replicationFactor, 
         Map<Node,NodeInfo> racksMap) {

          String [] retVal = new String[replicationFactor];

          List <NodeInfo> rackList = new LinkedList<NodeInfo>(); 

          rackList.addAll(racksMap.values());

        // Sort the racks based on their contribution to this split
          sortInDescendingOrder(rackList);

          boolean done = false;
          int index = 0;

        // Get the host list for all our aggregated items, sort
        // them and return the top entries
          for (NodeInfo ni: rackList) {

            Set<NodeInfo> hostSet = ni.getLeaves();

            List<NodeInfo>hostList = new LinkedList<NodeInfo>();
            hostList.addAll(hostSet);

          // Sort the hosts in this rack based on their contribution
            sortInDescendingOrder(hostList);

            for (NodeInfo host: hostList) {
            // Strip out the port number from the host name
              retVal[index++] = host.node.getName().split(":")[0];
              if (index == replicationFactor) {
                done = true;
                break;
              }
            }

            if (done == true) {
              break;
            }
          }
          return retVal;
        }

        private String[] fakeRacks(BlockLocation[] blkLocations, int index) 
        throws IOException {
          String[] allHosts = blkLocations[index].getHosts();
          String[] allTopos = new String[allHosts.length];
          for (int i = 0; i < allHosts.length; i++) {
            allTopos[i] = NetworkTopology.DEFAULT_RACK + "/" + allHosts[i];
          }
          return allTopos;
        }


        private static class NodeInfo {
          final Node node;
          final Set<Integer> blockIds;
          final Set<NodeInfo> leaves;

          private long value;

          NodeInfo(Node node) {
            this.node = node;
            blockIds = new HashSet<Integer>();
            leaves = new HashSet<NodeInfo>();
          }

          long getValue() {return value;}

          void addValue(int blockIndex, long value) {
            if (blockIds.add(blockIndex) == true) {
              this.value += value;
            }
          }

          Set<NodeInfo> getLeaves() { return leaves;}

          void addLeaf(NodeInfo nodeInfo) {
            leaves.add(nodeInfo);
          }
        }
      }
