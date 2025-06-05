async function fetchUsername() {
    const token = localStorage.getItem('token');
    if (!token) {
        document.getElementById("usernameDisplay").textContent = "⚠️ กรุณาเข้าสู่ระบบ";
        return;
    }

    try {
        const res = await fetch(`https://project-api-objectxify.onrender.com/get-username`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await res.json();
        if (res.ok && data.username) {
            document.getElementById("usernameDisplay").textContent = `👤 สวัสดีคุณ: ${data.username}`;
        } else {
            document.getElementById("usernameDisplay").textContent = `👤 ไม่พบชื่อผู้ใช้`;
        }
    } catch (err) {
        console.error("Error fetching username:", err);
        document.getElementById("usernameDisplay").textContent = `👤 ดึงชื่อผู้ใช้ไม่สำเร็จ`;
    }
}


// ฟังก์ชันในการดึงข้อมูล API Keys ของผู้ใช้
function fetchApiKeys() {
    const token = localStorage.getItem('token');
    if (!token) {
        document.getElementById("apiKeysList").innerHTML = "<p>⚠️ กรุณาเข้าสู่ระบบก่อน</p>";
        return;
    }

    fetch(`https://project-api-objectxify.onrender.com/get-api-keys`, {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            document.getElementById("apiKeysList").innerHTML = `<p>${data.error}</p>`;
        } else {
            let apiKeysHtml = "";
            data.api_keys.forEach(key => {
                apiKeysHtml += `
                    <div class="api-key">
                        <p><strong>API Key:</strong> ${key.api_key}</p>
                        <p><strong>Analysis Types:</strong> ${key.analysis_types.join(", ")}</p>
                        <p><strong>Quota:</strong> ${key.quota}</p>
                        <p><strong>Threshold:</strong> ${Object.entries(key.thresholds).map(([type, val]) => `${type}: ${val}`).join(", ")}</p>
                    </div>
                `;
            });
            document.getElementById("apiKeysList").innerHTML = apiKeysHtml;
        }
    })
    .catch(error => {
        console.error("Error fetching API keys:", error);
        document.getElementById("apiKeysList").innerHTML = "<p>เกิดข้อผิดพลาดในการดึงข้อมูล API Keys</p>";
    });
}

// โหลดข้อมูลเมื่อเปิดหน้า
window.onload = async function () {
    const token = localStorage.getItem('token');
    if (!token) {
        document.getElementById("usernameDisplay").textContent = "⚠️ กรุณาเข้าสู่ระบบ";
        return;
    }

    await fetchUsername();  // ✅ แก้ไขตรงนี้
    fetchApiKeys();
};

// ฟังก์ชันในการออกจากระบบ
function logout() {
    localStorage.removeItem('token'); // 🔒 ลบ token
    window.location.href = "../login-singup/login.html"; // 🔁 ย้ายกลับหน้า login
}


