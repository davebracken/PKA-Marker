#Sample PKA files.

There are 9 PKA files that can be used for marking.  These are PT version 8.2.2.0400 files.

The filename shows the score.

*Sample_Intro_Lab - Blank profile - Score 0.pka* is included to show what happens when a student merely submits an unattempted lab.

*Sample_Intro_Lab - First1 Last1 - Student name only -Score 0.pka* and *Sample_Intro_Lab - First2 Last2 - Student name and email - Score 0.pka* are included to show how they are reported in the CSV.

*Sample_Intro_Lab - First8 Last8 - Incorrect LabID - Score 100.pka* has a different LabID value.


The activity file password is cisco_activity
The LabID value is DB_IntroLab1 for all PKA's except the one mentioned above.

The original PKA is *ORG_Sample_Intro_Lab._pka_*  Rename it back to .pka if you want to modify the tests.

The PKT used to create the PKA is *DB_Sample_Intro_Lab.pkt*


The commands needed to score 100% in the lab are:
<pre>
hostname switch1
interface Vlan1
description Management interface
ip address 192.168.1.5 255.255.255.0
no shutdown

line con 0 
logging synchronous
</pre>

