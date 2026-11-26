import { expect, test } from "vitest";
import { formatPrice } from "./formatPrice.js";

test("formatPrice shows two decimal places", () => {
  expect(formatPrice(1250)).toBe("$12.50");
  expect(formatPrice(5)).toBe("$0.05");
  expect(formatPrice(300)).toBe("$3.00");
});
