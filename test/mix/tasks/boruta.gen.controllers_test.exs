defmodule Mix.Tasks.Boruta.Gen.ControllersTest do
  use ExUnit.Case

  @module_paths [
    "controllers/oauth/authorize_controller.ex",
    "controllers/openid/authorize_controller.ex",
    "controllers/openid/jwks_controller.ex",
    "controllers/oauth/token_controller.ex",
    "controllers/oauth/introspect_controller.ex",
    "controllers/oauth/revoke_controller.ex",
    "unit/oauth/controllers/authorize_controller_test.exs",
    "unit/oauth/controllers/token_controller_test.exs",
    "unit/oauth/controllers/introspect_controller_test.exs",
    "unit/oauth/controllers/revoke_controller_test.exs",
    "unit/openid/controllers/authorize_controller_test.exs",
    "unit/openid/controllers/jwks_controller_test.exs",
    "unit/openid/controllers/token_controller_test.exs",
    "views/oauth_view.ex",
    "views/openid_view.ex"
  ]

  test "compiles files without any errors" do
    Enum.map(@module_paths, fn path ->
      assert [{_module, _}|_t] =
               :code.priv_dir(:boruta)
               |> Path.join("templates/boruta.gen.controllers")
               |> Path.join(path <> ".eex")
               |> EEx.eval_file(
                 assigns: [web_module: "Boruta.Support.WebModule", otp_app: "boruta"]
               )
               |> Code.compile_string()
    end)
  end
end
