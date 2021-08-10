defmodule Mix.Tasks.Boruta.Gen.Controllers do
  @moduledoc """
  Boruta OAuth controllers generation task
  """

  use Mix.Task

  import Mix.Generator

  @module_paths [
    "controllers/oauth/authorize_controller.ex",
    "controllers/oauth/introspect_controller.ex",
    "controllers/oauth/revoke_controller.ex",
    "controllers/oauth/token_controller.ex",
    "views/oauth_view.ex"
  ]

  @raw_file_paths [
    "templates/oauth/error.html.eex"
  ]

  @test_files [
    "unit/oauth/controllers/authorize_controller_test.exs",
    "unit/oauth/controllers/introspect_controller_test.exs",
    "unit/oauth/controllers/revoke_controller_test.exs",
    "unit/oauth/controllers/token_controller_test.exs"
  ]

  def run(_args) do
    otp_app = Mix.Project.config() |> Keyword.fetch!(:app)
    web_app = :"#{otp_app}_web"

    assigns = [
      web_module: web_app |> Atom.to_string() |> Phoenix.Naming.camelize(),
      otp_app: otp_app,
      web_app: web_app
    ]

    copy_modules(otp_app, assigns)
    copy_raw_files(otp_app, assigns)
    copy_test_files(otp_app, assigns)

    IO.puts("""

    * Now you can add OAuth routes in application router as follow:

        scope "/oauth", MyAppWeb.Oauth do
          pipe_through :api

          post "/revoke", RevokeController, :revoke
          post "/token", TokenController, :token
          post "/introspect", IntrospectController, :introspect
        end

        scope "/oauth", MyAppWeb.Oauth do
          pipe_through [:browser]

          get "/authorize", AuthorizeController, :authorize
        end

    * Add following in config/config.exs

        config :myapp, :oauth_module, Boruta.Oauth

    ## Testing

    * Add following in config/test.exs

        config :myapp, :oauth_module, Boruta.OauthMock

    * Add following in test/test_helper.exs

        Mox.defmock(Boruta.OauthMock, for: Boruta.OauthModule)

    * Add mox dependency in order to run tests

        {:mox, "~> 0.5", only: :test},
    """)
  end

  defp copy_modules(otp_app, assigns) do
    List.zip([template_paths(@module_paths), @module_paths])
    |> Enum.map(fn {source, controller_path} ->
      target =
        otp_app
        |> Mix.Phoenix.web_path()
        |> Path.join(controller_path)

      copy_template(source, target, assigns)
    end)
  end

  defp copy_raw_files(otp_app, assigns) do
    List.zip([raw_file_paths(@raw_file_paths), @raw_file_paths])
    |> Enum.map(fn {source, controller_path} ->
      target =
        otp_app
        |> Mix.Phoenix.web_path()
        |> Path.join(controller_path)

      copy_file(source, target, assigns)
    end)
  end

  defp copy_test_files(otp_app, assigns) do
    List.zip([template_paths(@test_files), @test_files])
    |> Enum.map(fn {source, controller_path} ->
      target =
        otp_app
        |> Mix.Phoenix.web_test_path()
        |> Path.join(controller_path)

      copy_template(source, target, assigns)
    end)
  end

  defp template_paths(paths) do
    Enum.map(paths, &template_path/1)
  end

  defp template_path(path) do
    :code.priv_dir(:boruta)
    |> Path.join("templates/boruta.gen.controllers")
    |> Path.join(path <> ".eex")
  end

  defp raw_file_paths(paths) do
    paths
    |> Enum.map(fn path ->
      :code.priv_dir(:boruta)
      |> Path.join("templates/boruta.gen.controllers")
      |> Path.join(path)
    end)
  end
end
