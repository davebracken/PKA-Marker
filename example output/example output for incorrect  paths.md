# Nonexistent source PKA directory
PS C:\Users\Dave\downloads\pka_marker> .\PKA_marker.py --pka-dir c:\NoSuchDir
Argument error: PKA directory c:\NoSuchDir does not exist.

# Nonexistent source PKA file
PS C:\Users\Dave\downloads\pka_marker> .\PKA_marker.py --pka-file c:\NoSuchDir\NonexistentLabFile.pka
Argument error: PKA file c:\NoSuchDir\NonexistentLabFile.pka does not exist.

# Non existent path to potential output CSV file 
PS C:\Users\Dave\downloads\pka_marker> .\pka_marker.py --output-file C:\NoSuchDir\Results.csv
Argument error: Output directory C:\NoSuchDir does not exist.

# Present source PKA directory but non existent path to potential output CSV file 
PS C:\Users\Dave\downloads\pka_marker> .\pka_marker.py --pka-dir .\sample_pka_files\  --output-file C:\NoSuchDir\Results.csv
Argument error: Output directory C:\NoSuchDir does not exist.

# Non existent path to source PKA directory but existent path to potential output CSV file 
PS C:\Users\Dave\downloads\pka_marker> .\pka_marker.py --pka-dir C:\NoSuchDir\sample_pka_files\  --output-file ./Results.csv
Argument error: PKA directory C:\NoSuchDir\sample_pka_files\ does not exist.
