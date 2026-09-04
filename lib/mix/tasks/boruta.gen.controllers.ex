# Portions of this file are based on the Phoenix Framework's Mix generator tasks:
# https://github.com/phoenixframework/phoenix
#
# MIT License
#
# Copyright (c) 2014 Chris McCord
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# This file has been modified for Boruta. Boruta's modifications are licensed
# under the MIT License found in the repository's LICENSE file.

defmodule Mix.Tasks.Boruta.Gen.Controllers do
  @moduledoc """
  This task will help creation of a basic OAuth/OpenID Connect server by providing needed phoenix controllers, views and templates to expose OAuth endpoints.

  Controllers are unit tested using Mox, you'll need to add that dependency in order to run them (see below).

  ## Examples
  ```
  mix boruta.gen.controllers
  ```

  ## Post installation steps

  * You can add OAuth routes in web application router as follow to expose controller actions

  ```elixir
  scope "/oauth", MyAppWeb.Oauth do
    pipe_through :api

    post "/revoke", RevokeController, :revoke
    post "/token", TokenController, :token
    post "/introspect", IntrospectController, :introspect
  end

  scope "/openid", MyAppWeb.Openid do
    pipe_through [:api]

    get "/userinfo", UserinfoController, :userinfo
    post "/userinfo", UserinfoController, :userinfo
    get "/jwks", JwksController, :jwks_index
  end

  ####

  scope "/oauth", MyAppWeb.Oauth do
    pipe_through [:browser, :fetch_current_user]

    get "/authorize", AuthorizeController, :authorize
  end

  ## OR

  scope "/openid", MyAppWeb.Openid do
    pipe_through [:browser, :fetch_current_user]

    get "/authorize", AuthorizeController, :authorize
  end
  ```

  ### Testing

  * Add mox dependency in order to run controller unit tests

  ```elixir
  {:mox, "~> 0.5", only: :test}
  ```

  * Add following in config/test.exs

  ```elixir
  config :myapp, :oauth_module, Boruta.OauthMock
  config :myapp, :openid_module, Boruta.OpenidMock
  ```

  * Add following in test/test_helper.exs

  ```elixir
  Mox.defmock(Boruta.OauthMock, for: Boruta.OauthModule)
  Mox.defmock(Boruta.OpenidMock, for: Boruta.OpenidModule)
  ```

  ### User flows

  All flows involving resource owners need its integration guided by `Boruta.Oauth.ResourceOwners` behaviour.
  For authorize endpoint, you'll need to assign current_user with a plug and setup login redirections which, with raw setup, raise an error where it is required.
  """

  use Mix.Task

  import Mix.Generator

  @module_paths [
    "controllers/oauth/authorize_controller.ex",
    "controllers/openid/authorize_controller.ex",
    "controllers/openid/jwks_controller.ex",
    "controllers/openid/userinfo_controller.ex",
    "controllers/oauth/introspect_controller.ex",
    "controllers/oauth/revoke_controller.ex",
    "controllers/oauth/token_controller.ex",
    "views/oauth_view.ex",
    "views/openid_view.ex"
  ]

  @raw_file_paths [
    "templates/oauth/error.html.eex"
  ]

  @test_files [
    "unit/oauth/controllers/authorize_controller_test.exs",
    "unit/openid/controllers/authorize_controller_test.exs",
    "unit/openid/controllers/token_controller_test.exs",
    "unit/openid/controllers/jwks_controller_test.exs",
    "unit/openid/controllers/userinfo_controller_test.exs",
    "unit/oauth/controllers/introspect_controller_test.exs",
    "unit/oauth/controllers/revoke_controller_test.exs",
    "unit/oauth/controllers/token_controller_test.exs"
  ]

  def run(_args) do
    if Mix.Project.umbrella?() do
      Mix.raise(
        "mix boruta.gen.controllers must be invoked from within your *_web application root directory"
      )
    end

    otp_app = Mix.Phoenix.context_app()
    web_module = Mix.Phoenix.base() |> Mix.Phoenix.web_module()

    assigns = [
      web_module: Module.split(web_module) |> List.last(),
      otp_app: otp_app
    ]

    copy_modules(otp_app, assigns)
    copy_raw_files(otp_app)
    copy_test_files(otp_app, assigns)

    IO.puts("""

    * You can add OAuth routes in web application router as follow to expose controller actions

        scope "/oauth", MyAppWeb.Oauth do
          pipe_through :api

          post "/revoke", RevokeController, :revoke
          post "/token", TokenController, :token
          post "/introspect", IntrospectController, :introspect
        end


        scope "/openid", MyAppWeb.Openid do
          pipe_through [:api]

          get "/userinfo", UserinfoController, :userinfo
          post "/userinfo", UserinfoController, :userinfo
          get "/jwks", JwksController, :jwks_index
        end

        ####

        scope "/oauth", MyAppWeb.Oauth do
          pipe_through [:browser, :fetch_current_user]

          get "/authorize", AuthorizeController, :authorize
        end

        ## OR

        scope "/openid", MyAppWeb.Openid do
          pipe_through [:browser, :fetch_current_user]

          get "/authorize", AuthorizeController, :authorize
        end

    ### Testing

    * Add mox dependency in order to run controller unit tests

        {:mox, "~> 0.5", only: :test}

    * Add following in config/test.exs

        config :myapp, :oauth_module, Boruta.OauthMock
        config :myapp, :openid_module, Boruta.OpenidMock

    * Add following in test/test_helper.exs

        Mox.defmock(Boruta.OauthMock, for: Boruta.OauthModule)
        Mox.defmock(Boruta.OpenidMock, for: Boruta.OpenidModule)

    ### User flows

    All flows involving resource owners need its integration guided by `Boruta.Oauth.ResourceOwners` behaviour.
    For authorize endpoint, you'll need to assign current_user with a plug and setup login redirections which, with raw setup, raise an error where it is required.
    """)
  end

  defp copy_modules(otp_app, assigns) do
    Enum.zip([template_paths(@module_paths), @module_paths])
    |> Enum.map(fn {source, controller_path} ->
      target =
        otp_app
        |> Mix.Phoenix.web_path()
        |> Path.join(controller_path)

      copy_template(source, target, assigns)
    end)
  end

  defp copy_raw_files(otp_app) do
    Enum.zip([raw_file_paths(@raw_file_paths), @raw_file_paths])
    |> Enum.map(fn {source, controller_path} ->
      target =
        otp_app
        |> Mix.Phoenix.web_path()
        |> Path.join(controller_path)

      copy_file(source, target)
    end)
  end

  defp copy_test_files(otp_app, assigns) do
    Enum.zip([template_paths(@test_files), @test_files])
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
