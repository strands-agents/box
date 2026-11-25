import { total } from './total.js'

export function report(items){
    if (!items) {}
    return `total: ${total(items)}`
}
