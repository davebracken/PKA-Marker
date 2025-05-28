# The command line help can be invoked using --help or -h
<pre>
PS C:\Users\Dave\Downloads\pka_marker> .\pka_marker.py --help
usage: pka_marker.py [-h] [--data-store-id DATA_STORE_ID] [--log-file LOG_FILE] [--no-console] [--no-csv] [--no-lab-id]
                     [--output-file OUTPUT_FILE] [--pka-dir PKA_DIR] [--pka-file PKA_FILE]
                     [--score-rounding-dp SCORE_ROUNDING_DP] [--test-connection] [--verbose] [--version]

Super Duper Automagic PKA marker.
Dave Bracken.
Version: 1.0.1

options:
  -h, --help                             show this help message and exit
  --data-store-id DATA_STORE_ID          Data store ID to use for lab ID. (default: None)
  --log-file LOG_FILE                    Path to log file. This enables the verbose option. (default: None)
  --no-console                           Disable console output. (default: False)
  --no-csv                               Send results to the console, not CSV. (default: False)
  --no-lab-id                            Do not include the Lab ID. (default: False)
  --output-file OUTPUT_FILE              Path to output CSV file. (default: None)
  --pka-dir PKA_DIR                      Path to directory containing PKA files to process. (default: None)
  --pka-file PKA_FILE                    Path to a single PKA file to process. (default: None)
  --score-rounding-dp SCORE_ROUNDING_DP  Number of decimal places to round the lab score. (default: 1)
  --test-connection                      Test connection to Packet Tracer without marking PKAs. (default: False)
  --verbose, -v                          Enable verbose logging. (default: False)
  --version, -V                          Show program version.
</pre>
<pre>
PS C:\Users\Dave\Downloads\pka_marker> .\pka_marker.py -h
usage: pka_marker.py [-h] [--data-store-id DATA_STORE_ID] [--log-file LOG_FILE] [--no-console] [--no-csv] [--no-lab-id]
                     [--output-file OUTPUT_FILE] [--pka-dir PKA_DIR] [--pka-file PKA_FILE]
                     [--score-rounding-dp SCORE_ROUNDING_DP] [--test-connection] [--verbose] [--version]

Super Duper Automagic PKA marker.
Dave Bracken.
Version: 1.0.1

options:
  -h, --help                             show this help message and exit
  --data-store-id DATA_STORE_ID          Data store ID to use for lab ID. (default: None)
  --log-file LOG_FILE                    Path to log file. This enables the verbose option. (default: None)
  --no-console                           Disable console output. (default: False)
  --no-csv                               Send results to the console, not CSV. (default: False)
  --no-lab-id                            Do not include the Lab ID. (default: False)
  --output-file OUTPUT_FILE              Path to output CSV file. (default: None)
  --pka-dir PKA_DIR                      Path to directory containing PKA files to process. (default: None)
  --pka-file PKA_FILE                    Path to a single PKA file to process. (default: None)
  --score-rounding-dp SCORE_ROUNDING_DP  Number of decimal places to round the lab score. (default: 1)
  --test-connection                      Test connection to Packet Tracer without marking PKAs. (default: False)
  --verbose, -v                          Enable verbose logging. (default: False)
</pre>  
  --version, -V                          Show program version.
