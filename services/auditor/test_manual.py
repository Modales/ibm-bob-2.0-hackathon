from taint_scan import scan_file

print("Vulnerable file result:")
print(scan_file("test_samples/vulnerable.py"))

print("Safe file result:")
print(scan_file("test_samples/safe.py"))

print("False positive check:")
print(scan_file("test_samples/false_positive.py"))
