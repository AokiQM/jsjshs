const express = require("express");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE
);

// 验证卡密
app.post("/verify", async (req, res) => {
  const { key, device_id } = req.body;

  const { data, error } = await supabase
    .from("keys")
    .select("*")
    .eq("key", key)
    .single();

  if (error || !data) {
    return res.json({ success: false, message: "卡密不存在" });
  }

  if (data.status !== "active") {
    return res.json({ success: false, message: "卡密不可用" });
  }

  if (new Date(data.expires_at) < new Date()) {
    return res.json({ success: false, message: "卡密已过期" });
  }

  if (data.device_id && data.device_id !== device_id) {
    return res.json({ success: false, message: "设备不匹配" });
  }

  if (!data.device_id) {
    await supabase
      .from("keys")
      .update({ device_id })
      .eq("key", key);
  }

  return res.json({ success: true });
});

app.listen(3000, () => {
  console.log("Server running");
});
