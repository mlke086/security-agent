import { Modal, Form, Input, message } from "antd"
import { useAuth } from "../context/AuthContext"
import { changePassword } from "../api/client"

/** Modal for changing the current user's password. Extracted from
 *  AppLayout so the layout component stays focused on chrome and
 *  the password form gets its own concern (Divergent Change guard,
 *  V9 4.5). Mounted by AppLayout and triggered from the header
 *  username menu. The owning component owns the visibility state.
 *
 *  V10 1.4: after a successful change we force a re-login. The
 *  password rotation bumps users.token_version (V9 2.1), so the
 *  current JWT is invalid -- calling AuthContext.logout() clears
 *  the local token + user state and the App router redirects to
 *  /login via <Navigate to="/login" />.
 */
export default function ChangePasswordModal({
  open,
  onClose,
}: { open: boolean; onClose: () => void }) {
  const [form] = Form.useForm()
  const { logout } = useAuth()
  const handleOk = async () => {
    try {
      const values = await form.validateFields()
      await changePassword(values.oldPassword, values.newPassword)
      message.success("密码已修改，请重新登录")
      form.resetFields()
      onClose()
      // V10 1.4: old JWT was invalidated by the token_version bump.
      // logout() drops the local token; the router redirects to /login.
      logout()
    } catch (error: any) {
      if (!error?.errorFields) {
        message.error(error?.response?.data?.detail || "修改密码失败")
      }
    }
  }
  return (
    <Modal
      title="修改密码"
      open={open}
      onCancel={() => { form.resetFields(); onClose() }}
      onOk={handleOk}
      okText="确认修改"
      cancelText="取消"
    >
      <Form form={form} layout="vertical">
        <Form.Item name="oldPassword" label="当前密码" rules={[{ required: true, message: "请输入当前密码" }]}>
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Form.Item name="newPassword" label="新密码" rules={[{ required: true }, { min: 12, message: "密码至少 12 位" }]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        <Form.Item
          name="confirmPassword"
          label="确认新密码"
          dependencies={["newPassword"]}
          rules={[
            { required: true },
            ({ getFieldValue }) => ({
              validator(_, value) {
                return !value || getFieldValue("newPassword") === value
                  ? Promise.resolve()
                  : Promise.reject(new Error("两次输入的密码不一致"))
              },
            }),
          ]}
        >
          <Input.Password autoComplete="new-password" />
        </Form.Item>
      </Form>
    </Modal>
  )
}
