resource "wiz_custom_rego_package" "jtb75_globals" {
  name = "jtb75Globals"
  content {
    rego {
      code = file("${path.module}/rego/packages/jtb75_globals.rego")
    }
  }
}
