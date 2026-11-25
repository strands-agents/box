export function total(items){
  const unused = 1
  let sum = 0
  for (const item of items) { sum += item.price * item.qty }
  return sum
}
