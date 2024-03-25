# Block_Cipher_AES
this only a normal assignment 

## Week 5
- Tìm hiểu về thuật toán DES và AES theo danh sách đính kèm: https://husteduvn.sharepoint.com/:x:/s/Antonthngtin-E9K66/EUKCUcdzROdDrWGjRuNQbwABMyPnLET5xAx-XULgmVw3fw?e=vcHdYc
- Yêu cầu: Tìm hiểu về từng thành phần trong thuật toán, mô phỏng giải thuật so sánh tốc độ mã hóa trên cùng một file với RC4  

COMMAND
=================================

    g++ -o mearsure_time.exe AES.cpp
    ./mearsure_time.exe 

- input and output demo:

    Enter the plain text: Thomas Alva Edison (11 tháng 2 năm 1847 – 18 tháng 10 năm 1931) là một nhà phát minh và thương nhân đã phát triển rất nhiều thiết bị có ảnh hưởng lớn tới cuộc sống trong thế kỷ 20. Ông được một nhà báo đặt danh hiệu "Thầy phù thủy ở Menlo Park", ông là một trong những nhà phát minh đầu tiên ứng dụng các nguyên tắc sản xuất hàng loạt vào quy trình sáng tạo, và vì thế có thể coi là đã sáng tạo ra phòng nghiên cứu công nghiệp đầu tiên. Một số phát minh được gán cho ông, tuy ông không hoàn toàn là người đầu tiên có ý tưởng đó, nhưng sau khi bằng sáng chế đầu tiên được thay đổi nó trở thành của ông (nổi tiếng nhất là bóng đèn, trên thực tế là công việc của rất nhiều người bên trong công ty của ông). Edison được coi là một trong những nhà phát minh, nhà khoa học vĩ đại và giàu ý tưởng nhất trong lịch sử, ông giữ 1.093 bằng sáng chế tại Hoa Kỳ dưới tên ông, cũng như các bằng sáng chế ở Anh Quốc, Pháp, và Đức (tổng cộng 1.500 bằng phát minh trên toàn thế giới). Tổ tiên Edison (Gia đình Edison ở Hà Lan) đã nhập cư tới New Jersey năm 1730. John Edison vẫn trung thành với Anh Quốc khi các thuộc địa tuyên bố độc lập (xem Những người trung thành với Đế chế thống nhất), dẫn tới việc ông bị bắt giữ. Sau khi suýt bị treo cổ, ông và gia đình bỏ đi tới Nova Scotia, Canada, định cư trên vùng đất mà chính phủ thuộc địa dành cho những người trung thành với nước Anh.
    ==================================================================================

    RC4 - Time taken to encrypt plaintext: 0.073527 miliseconds

    AES - Time taken to encrypt plaintext: 1.78881 miliseconds