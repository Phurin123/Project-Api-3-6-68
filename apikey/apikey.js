async function generateApiKey() {
    const token = localStorage.getItem('token');
    if (!token) {
        alert("กรุณาล็อกอินก่อน");
        return;
    }

    let analysisTypes = [];
    document.querySelectorAll('.analysis-option:checked').forEach(option => {
        analysisTypes.push(option.value);
    });

    let quota = parseInt(document.getElementById("quota").value);
    if (analysisTypes.length === 0 || isNaN(quota) || quota < 100) {
        alert("กรุณากรอกข้อมูลทั้งหมดให้ถูกต้อง");
        return;
    }

    let thresholds = {};
    analysisTypes.forEach(type => {
        let slider = document.getElementById(type + "-threshold");
        if (slider) {
            thresholds[type] = parseFloat(slider.value);
        }
    });

    let amount = quota / 100;

    // เรียก backend เพื่อสร้าง QR และ ref_code
    try {
        const response = await fetch("https://project-api-objectxify.onrender.com/generate_qr", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`  // <<-- แนบ token แทน email
            },
            body: JSON.stringify({
                amount: amount,
                quota: quota,
                plan: "paid",
                analysis_types: analysisTypes,
                thresholds: thresholds
            })
        });

        const data = await response.json();

        if (!response.ok) {
            alert(data.error || "เกิดข้อผิดพลาดในการสร้าง QR Code");
            return;
        }

        // เก็บข้อมูลลง sessionStorage
        sessionStorage.setItem("selectedQuota", quota);
        sessionStorage.setItem("selectedAmount", amount);
        sessionStorage.setItem("selectedAnalysis", JSON.stringify(analysisTypes));
        sessionStorage.setItem("selectedThresholds", JSON.stringify(thresholds));
        sessionStorage.setItem("qr_code_url", data.qr_code_url);
        sessionStorage.setItem("ref_code", data.ref_code);

        // ไปหน้าชำระเงิน
        window.location.href = "payment.html";

    } catch (err) {
        console.error("Error:", err);
        alert("ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้");
    }
}
