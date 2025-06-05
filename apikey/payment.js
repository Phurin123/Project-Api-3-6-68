document.addEventListener('DOMContentLoaded', function () {
  const token = localStorage.getItem("token");
  const amount = sessionStorage.getItem("selectedAmount");
  const quota = sessionStorage.getItem("selectedQuota");
  const analysisTypes = JSON.parse(sessionStorage.getItem("selectedAnalysis"));
  const thresholds = JSON.parse(sessionStorage.getItem("selectedThresholds"));
  const amountSpan = document.getElementById('amount');
  const qrCodeImage = document.getElementById('qrCodeImage');
  const paymentStatus = document.getElementById('paymentStatus');
  const refCodeDisplay = document.getElementById('refCodeDisplay');

  if (!token) {
        alert("กรุณาล็อกอินก่อน");
        return;
    }
    
  // แสดงจำนวนเงิน
  if (amountSpan) {
    amountSpan.innerText = amount;
  }

  // ถ้ามีอยู่แล้วใน sessionStorage ให้แสดงเลย
  const existingQrUrl = sessionStorage.getItem("qr_code_url");
  const existingRefCode = sessionStorage.getItem("ref_code");

  if (existingQrUrl && existingRefCode) {
    qrCodeImage.src = existingQrUrl;
    refCodeDisplay.textContent = existingRefCode;
    return; // ไม่ต้อง fetch ซ้ำ
  }

  // เรียก API เพื่อสร้าง QR Code ใหม่
  fetch('https://project-api-objectxify.onrender.com/generate_qr', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({
      amount: parseFloat(amount),
      quota: parseInt(quota),
      analysis_types: analysisTypes,
      thresholds: thresholds
    })
  })
  .then(res => res.json())
  .then(data => {
    if (data.qr_code_url && data.ref_code) {
      qrCodeImage.src = data.qr_code_url;
      refCodeDisplay.textContent = data.ref_code;

      // บันทึกลง sessionStorage
      sessionStorage.setItem("qr_code_url", data.qr_code_url);
      sessionStorage.setItem("ref_code", data.ref_code);
    } else {
      paymentStatus.textContent = "ไม่สามารถสร้าง QR Code ได้";
    }
  })
  .catch(err => {
    console.error("Error:", err);
    paymentStatus.textContent = "เกิดข้อผิดพลาดในการเชื่อมต่อเซิร์ฟเวอร์";
  });
});

// ฟังก์ชันสำหรับปุ่มคัดลอก
function copyRefCode() {
const refCode = document.getElementById('refCodeDisplay').textContent;
navigator.clipboard.writeText(refCode)
}
