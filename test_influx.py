import os
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

try:
    with open("/home/ubuntu/ddos-tool/influx_token.txt") as f:
        token = f.read().strip()
        
    client = InfluxDBClient(url="http://localhost:8086", token=token, org="ddos-lab")
    write_api = client.write_api(write_options=SYNCHRONOUS)

    p = Point("traffic_metrics").tag("host", "test").field("pps", 9999)
    write_api.write(bucket="traffic", org="ddos-lab", record=p)
    print("✅ SUCCESS: Data written perfectly! The problem is in Grafana.")
except Exception as e:
    print(f"❌ ERROR: The database rejected the data: {e}")
