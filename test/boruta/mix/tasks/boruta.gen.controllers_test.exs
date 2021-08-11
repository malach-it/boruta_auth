defmodule Mix.Tasks.Boruta.Gen.ControllersTest do
  use ExUnit.Case

  @module_paths [
    "controllers/oauth/authorize_controller.ex",
    "controllers/oauth/introspect_controller.ex",
    "controllers/oauth/revoke_controller.ex",
    "controllers/oauth/token_controller.ex",
    "views/oauth_view.ex"
  ]

  test "compiles files without any errors" do
    Enum.map(@module_paths, fn path ->
      assert [{_module, _}] =
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
