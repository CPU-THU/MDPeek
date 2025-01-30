objdump -d enclave.signed.so | grep "<mbedtls_mpi_inv_mod>:" -A 3000 > objdump_mbedtls_mpi_inv_mod.txt

echo "stld_1 (0x24e33):"
objdump -d app | grep "<stld_1>:" -A 30 | grep "8b 06"

echo "stld_2 (0x253ae):"
objdump -d app | grep "<stld_2>:" -A 30 | grep "8b 06"

echo "stld_3 (0x25005):"
objdump -d app | grep "<stld_3>:" -A 30 | grep "8b 06"

echo "stld_4 (0x25580):"
objdump -d app | grep "<stld_4>:" -A 30 | grep "8b 06"

echo "stld_5 (0x251d7):"
objdump -d app | grep "<stld_5>:" -A 30 | grep "8b 06"

echo "stld_6 (0x256e0):"
objdump -d app | grep "<stld_6>:" -A 30 | grep "8b 06"