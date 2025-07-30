from teacher_identification import teacher
from student_identification import student

while True:
    print("="*100)
    print("Welcome to ABC Academy App".center(100))
    print("="*100)
    try:
        identity = input("Are you a student or a teacher?:").lower().strip()
        if identity not in ['student','teacher']:
            raise ValueError
    except ValueError:
        print("Error, Enter a valid identity")
        continue
    if identity == "student":
        student()
        break
    elif identity == "teacher":
        teacher()
        break


 




