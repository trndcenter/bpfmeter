# Metrics

There are 4 types of metrics that can be exported in OpenMetrics format or saved to a file: 3 metrics for eBPF programs and 1 for eBPF maps. By default, metrics are collected every 30 seconds.

## eBPF Program Measurements

### CPU Usage
- **Name**: `ebpf_cpu_usage`
- **Type**: gauge
- **Unit**: percent (float, 1.0 = 100%)
- **Description**: The current CPU usage of the application as a ratio. Can be greater than 1.0 if more than one core is used.

### Run Time
- **Name**: `ebpf_run_time`
- **Type**: gauge
- **Unit**: seconds (float)
- **Description**: Cumulative CPU time spent executing the eBPF program. Can be greater than zero at startup if some measurements were already performed previously.

### Event Count
- **Name**: `ebpf_event_count`
- **Type**: gauge
- **Unit**: number of runs
- **Description**: Total number of times the eBPF program was executed (or number of events that triggered the corresponding eBPF program). Can be greater than zero at startup if some measurements were already performed previously.

Common labels:
* `ebpf_id` - ID of eBPF program
* `ebpf_name` - name of eBPF program

## eBPF Map Measurements

### Map Size
- **Name**: `ebpf_map_size`
- **Type**: gauge
- **Unit**: number of elements in map
- **Description**: The current size of the eBPF map. Size tracking is supported for the following map types: `Hash`, `PerCpuHash`, `LruHash`, `LruPerCpuHash`.
- **Labels**:
    * `ebpf_map_id` - ID of eBPF map
    * `ebpf_map_name` - name of eBPF map
    * `ebpf_map_max_size` - maximum size of current map
