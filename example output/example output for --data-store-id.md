# The example labs only have LabID as the added ID in the data store.

PS C:\Users\Dave\downloads\pka_marker> .\pka_marker.py --data-store-id LabID
student_full_name,student_email_addr,lab_score,rounded_lab_score,lab_id
First1 Last1,,0.0,0.0,DB_IntroLab1
First2 Last2,First2.Last2@students.mega_poly_one.ac.nz,0.0,0.0,DB_IntroLab1
First3 Last3,First3.Last3@students.mega_poly_one.ac.nz,16.6667,16.7,DB_IntroLab1
First4 Last4,First4.Last4@students.mega_poly_one.ac.nz,33.3333,33.3,DB_IntroLab1
First5 Last5,First5.Last5@students.mega_poly_one.ac.nz,66.6667,66.7,DB_IntroLab1
First6 Last6,First6.Last6@students.mega_poly_one.ac.nz,83.3333,83.3,DB_IntroLab1
First7 Last7,First7.Last7@students.mega_poly_one.ac.nz,100.0,100.0,DB_IntroLab1
First8 Last8,First8.Last8@students.mega_poly_one.ac.nz,100.0,100.0,DB_IntroLab1-2024
Guest,,0.0,0.0,DB_IntroLab1


PS C:\Users\Dave\downloads\pka_marker> .\pka_marker.py --data-store-id aDifferentID
student_full_name,student_email_addr,lab_score,rounded_lab_score,lab_id
First1 Last1,,0.0,0.0,
First2 Last2,First2.Last2@students.mega_poly_one.ac.nz,0.0,0.0,
First3 Last3,First3.Last3@students.mega_poly_one.ac.nz,16.6667,16.7,
First4 Last4,First4.Last4@students.mega_poly_one.ac.nz,33.3333,33.3,
First5 Last5,First5.Last5@students.mega_poly_one.ac.nz,66.6667,66.7,
First6 Last6,First6.Last6@students.mega_poly_one.ac.nz,83.3333,83.3,
First7 Last7,First7.Last7@students.mega_poly_one.ac.nz,100.0,100.0,
First8 Last8,First8.Last8@students.mega_poly_one.ac.nz,100.0,100.0,
Guest,,0.0,0.0,
