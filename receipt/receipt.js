document.addEventListener('DOMContentLoaded', function() {
    const uploadBtn = document.getElementById('uploadBtn');
    const uploadStatus = document.getElementById('uploadStatus');
    const receiptImage = document.getElementById('receiptImage');
    const apiKeyDisplay = document.getElementById('api_key');  // id สำหรับโชว์ API Key

    if (uploadBtn && uploadStatus && receiptImage && apiKeyDisplay) {
        uploadBtn.addEventListener('click', async function() {
            const file = receiptImage.files[0];
            if (!file) {
                uploadStatus.textContent = 'กรุณาเลือกไฟล์ใบเสร็จ';
                return;
            }

            const token = localStorage.getItem('token');
            if (!token) {
                uploadStatus.textContent = '⚠️ กรุณาเข้าสู่ระบบก่อน';
                return;
            }

            const formData = new FormData();
            formData.append('receipt', file);

            try {
                const response = await fetch('https://project-api-objectxify.onrender.com/upload-receipt', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`  // 👈 แนบ JWT ตรงนี้
                    },
                    body: formData
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    uploadStatus.textContent = '✅ อัปโหลดสำเร็จ!';
                    apiKeyDisplay.textContent = data.api_key;  // แสดง API Key ที่ได้รับ
                } else {
                    uploadStatus.textContent = '❌ เกิดข้อผิดพลาด: ' + (data.error || 'ไม่ทราบสาเหตุ');
                    apiKeyDisplay.textContent = '';
                }
            } catch (error) {
                console.error('เกิดข้อผิดพลาด:', error);
                uploadStatus.textContent = '❌ ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์';
                apiKeyDisplay.textContent = '';
            }
        });
    }
});
