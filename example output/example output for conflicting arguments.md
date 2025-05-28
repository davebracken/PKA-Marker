# Effectively specifying no output
<pre>
PS C:\Users\Dave\downloads\pka_marker> .\pka_marker.py --no-csv --no-console
Argument error: Cannot specify both --no-console and --no_csv-.
</pre>

# Attempting to specify a directory to process as well as a single file
<pre>
PS C:\Users\Dave\downloads\pka_marker> .\pka_marker.py --pka-dir ./sample_pka_files\  --pka-file '.\sample_pka_files\Sample_Intro_Lab - First1 Last1 - Student name only -Score 0.pka'
Argument error: Specify either --pka-file or --pka-dir.
</pre>
