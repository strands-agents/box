import { formatPrice } from "@shop/format";

export function total(items) {
  return formatPrice(items.reduce((sum, item) => sum + item.cents * item.qty, 0));
}
