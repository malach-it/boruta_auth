defmodule Boruta.TokenGenerator do
  @moduledoc false

  @behaviour Boruta.Oauth.TokenGenerator

  use Puid, bits: 512, charset: :alphanum

  @impl Boruta.Oauth.TokenGenerator
  def generate(_, _) do
    generate()
  end

  @impl Boruta.Oauth.TokenGenerator
  def secret(_) do
    generate()
  end
end
