defmodule Boruta.TokenGeneratorTest do
  use ExUnit.Case, async: true

  alias Boruta.TokenGenerator

  test "generates 512-bit alphanumeric tokens" do
    token = TokenGenerator.generate()

    assert String.length(token) == 86
    assert token =~ ~r/^[A-Za-z0-9]+$/
  end

  test "generates four-digit transaction codes" do
    tx_code = TokenGenerator.generate(:tx_code, nil)

    assert String.length(tx_code) == TokenGenerator.tx_code_length()
    assert tx_code =~ ~r/^\d{4}$/
  end
end
