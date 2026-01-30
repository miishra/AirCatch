import serial
import time
from datetime import datetime

# Replace with your ESP port
ser = serial.Serial('/dev/ttyACM1', 115200, timeout=1)

buffer_size = 4096  # match firmware buffer size
total_bytes = 0
errors = 0

# Create output filenames
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
filename = "rail_data_jan29"
output_file = filename + ".bin"
timestamps_file = filename + "_timestamps.csv"

print(f"Starting capture...")
print(f"Output file: {output_file}")
print(f"Press Ctrl+C to stop\n")

start_time = time.time()

try:
    with open(output_file, 'wb') as f_data, open(timestamps_file, 'w', encoding='ascii') as f_ts:
        f_ts.write("chunk_index,byte_offset,chunk_size,elapsed_seconds,epoch_seconds,iso_timestamp\n")

        chunk_index = 0

        while True:
            data = ser.read(buffer_size)
            
            if len(data) > 0:
                chunk_index += 1
                chunk_time = time.time()
                elapsed = chunk_time - start_time
                byte_offset = total_bytes  # offset before writing this chunk
                
                # Write raw data to file
                f_data.write(data)
                total_bytes += len(data)

                # Log timestamp metadata for this chunk (decoder can map offsets -> timestamps)
                iso_ts = datetime.fromtimestamp(chunk_time).isoformat()
                f_ts.write(f"{chunk_index},{byte_offset},{len(data)},{elapsed:.6f},{chunk_time:.6f},{iso_ts}\n")

                # Print progress roughly every second
                if int(elapsed) > int(elapsed - 0.1):
                    throughput = total_bytes / elapsed / 1024
                    print(f"\rReceived: {total_bytes / 1024:.2f} KB | "
                          f"Throughput: {throughput:.2f} KB/s | "
                          f"Time: {int(elapsed)}s", end='')

except KeyboardInterrupt:
    print("\n\nCapture stopped by user")

finally:
    end_time = time.time()
    elapsed = end_time - start_time
    
    ser.close()
    
    print(f"\n\n{'='*50}")
    print(f"Capture Summary")
    print(f"{'='*50}")
    print(f"Output file: {output_file}")
    print(f"Timestamps file: {timestamps_file}")
    print(f"Total bytes: {total_bytes:,} ({total_bytes / 1024 / 1024:.2f} MB)")
    print(f"Duration: {elapsed:.2f} seconds")
    print(f"Average throughput: {total_bytes / elapsed / 1024:.2f} KB/s")
    print(f"                    {total_bytes / elapsed / 1024 / 1024:.2f} MB/s")
    print(f"{'='*50}")