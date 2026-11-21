import { expect, test } from "vitest";
import { total } from "./total.js";

test("total sums the items", () => {
  expect(total([{ cents: 250, qty: 2 }, { cents: 199, qty: 1 }])).toBe("$6.99");
});
