"use strict";
async function addCart(id, quantity) {
    console.log(id, quantity);
    let res = await fetch("/products/cart", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
        },
        body: JSON.stringify({ id, quantity }),
    });
    let json = await res.json();
    document.getElementById("cart-quantity").innerText = `(${json.quantity})`;
}

async function updateCart(id, quantity) {
    if (quantity > 0) {
        console.log(id, quantity);
        let res = await fetch(`/products/cart`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body: JSON.stringify({ id, quantity }),
        });
        if (res.status === 200) {
            let json = await res.json();
            document.getElementById("cart-quantity").innerText =
                `(${json.quantity})`;

            document.getElementById("subtotal").innerText = `$${json.subtotal}`;
            document.getElementById("total").innerText = `$${json.total}`;
            document.getElementById(`total${id}`).innerText =
                `$${json.item.total}`;
            console.log(`total${id}`);
        }
    } else {
        removeCart(id);
    }
}

async function removeCart(id) {
    if (
        confirm("Are you sure you want to remove this product from the cart?")
    ) {
        console.log(id);
        let res = await fetch(`/products/cart/${id}`, {
            method: "DELETE",
        });
        if (res.status === 200) {
            let json = await res.json();
            document.getElementById(`row${id}`).remove();
            document.getElementById("subtotal").innerText = `$${json.subtotal}`;
            document.getElementById("total").innerText = `$${json.total}`;
            document.getElementById("cart-quantity").innerText =
                `(${json.quantity})`;
        }
    }
}

async function placeorders(e) {
    e.preventDefault();
    const addressId = document.querySelector("input[name=addressId]:checked");
    if (!addressId || addressId.value == 0) {
        if (!e.target.checkValidity()) {
            return e.target.reportValidity();
        }
    }

    e.target.submit();
}
