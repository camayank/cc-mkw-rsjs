"""CyberComply — Stripe billing: customer, invoice, subscription, webhook handling."""
import os
import logging

logger = logging.getLogger("cybercomply.billing")

try:
    import stripe
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
except ImportError:
    stripe = None
    logger.warning("stripe package not installed — billing disabled")


def get_or_create_customer(client_profile: dict) -> str:
    """Get existing or create new Stripe customer. Returns customer ID."""
    if not stripe:
        raise RuntimeError("stripe package not installed")

    existing_id = client_profile.get("stripe_customer_id")
    if existing_id:
        try:
            stripe.Customer.retrieve(existing_id)
            return existing_id
        except stripe.error.InvalidRequestError:
            pass  # Customer deleted in Stripe, create new

    customer = stripe.Customer.create(
        name=client_profile.get("company_name", ""),
        email=client_profile.get("contact_email", ""),
        metadata={
            "client_id": client_profile.get("client_id", ""),
            "domain": client_profile.get("domain", ""),
        },
    )
    return customer.id


def create_invoice(customer_id: str, items: list, due_days: int = 7) -> dict:
    """
    Create and send a Stripe invoice.
    Args:
        customer_id: Stripe customer ID
        items: List of dicts with 'description', 'amount' (in dollars), optional 'recurring'
        due_days: Days until due
    Returns: dict with invoice_id, invoice_url, subscription_id, status
    """
    if not stripe:
        raise RuntimeError("stripe package not installed")

    one_time_items = [i for i in items if not i.get("recurring")]
    recurring_items = [i for i in items if i.get("recurring")]

    result = {"invoice_id": None, "invoice_url": None, "subscription_id": None, "status": "created"}

    # One-time invoice
    if one_time_items:
        invoice = stripe.Invoice.create(
            customer=customer_id,
            collection_method="send_invoice",
            days_until_due=due_days,
        )
        for item in one_time_items:
            amount_cents = int(item["amount"] * 100)  # dollars to cents
            stripe.InvoiceItem.create(
                customer=customer_id,
                invoice=invoice.id,
                amount=amount_cents,
                currency="usd",
                description=item["description"],
            )
        invoice = stripe.Invoice.finalize_invoice(invoice.id)
        stripe.Invoice.send_invoice(invoice.id)
        result["invoice_id"] = invoice.id
        result["invoice_url"] = invoice.hosted_invoice_url
        result["status"] = "sent"

    # Recurring subscriptions
    if recurring_items:
        for item in recurring_items:
            amount_cents = int(item["amount"] * 100)
            price = stripe.Price.create(
                unit_amount=amount_cents,
                currency="usd",
                recurring={"interval": "month"},
                product_data={"name": item["description"]},
            )
            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{"price": price.id}],
            )
            result["subscription_id"] = subscription.id

    return result


def handle_webhook(payload: bytes, sig_header: str) -> dict:
    """
    Verify and process a Stripe webhook event.
    IMPORTANT: Tier promotion ONLY on subscription events, NOT one-time invoice payments.
    """
    if not stripe:
        raise RuntimeError("stripe package not installed")

    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not webhook_secret:
        raise ValueError("STRIPE_WEBHOOK_SECRET not configured")

    event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)

    event_type = event["type"]
    data = event["data"]["object"]
    customer_id = data.get("customer")

    # Retrieve client_id from customer metadata
    client_id = ""
    if customer_id:
        try:
            customer = stripe.Customer.retrieve(customer_id)
            client_id = customer.get("metadata", {}).get("client_id", "")
        except Exception:
            pass

    result = {
        "event_type": event_type,
        "client_id": client_id,
        "customer_id": customer_id,
        "action": "none",
        "details": {},
    }

    if event_type in ("customer.subscription.created", "customer.subscription.updated"):
        # Determine tier from annual subscription amount (in cents).
        # Flagship clients are annual prepaid only — interval=year is required.
        items = data.get("items", {}).get("data", [])
        total_cents = 0
        for item in items:
            price = item.get("price") or {}
            unit_amount = price.get("unit_amount", 0) or 0
            recurring = price.get("recurring") or {}
            interval = recurring.get("interval", "")
            interval_count = recurring.get("interval_count", 1) or 1
            # Normalize to annual cents.
            if interval == "year":
                annual = unit_amount * interval_count
            elif interval == "month":
                # Monthly subscriptions are not a supported tier model for
                # flagship clients — extrapolate to annual for tier mapping
                # but flag this for operator review.
                annual = unit_amount * 12 * interval_count
                result.setdefault("warnings", []).append(
                    "monthly_billing_not_supported_for_flagship_tier"
                )
            else:
                annual = unit_amount
            total_cents += annual

        # Tier thresholds match commercial tiers.
        if total_cents >= 9_600_000:        # $96,000+/yr
            new_tier = "enterprise_plus"
        elif total_cents >= 4_800_000:      # $48,000+/yr
            new_tier = "professional"
        elif total_cents >= 2_400_000:      # $24,000+/yr
            new_tier = "essentials"
        else:
            # Below the lowest retainer floor — keep prior tier untouched.
            # Operator should review; do not silently demote to a paid tier.
            new_tier = "diagnostic"
        result["action"] = "update_tier"
        result["details"] = {"tier": new_tier, "annual_cents": total_cents}

    elif event_type == "customer.subscription.deleted":
        # Subscription ended — drop back to diagnostic (one-time engagement
        # state). Portal access is gated server-side based on tier config.
        result["action"] = "downgrade_tier"
        result["details"] = {"tier": "diagnostic"}

    elif event_type == "invoice.paid":
        # Only update payment status, NOT tier
        subscription_id = data.get("subscription")
        result["action"] = "mark_paid"
        result["details"] = {
            "invoice_id": data.get("id"),
            "amount_paid": data.get("amount_paid", 0),
            "is_subscription": subscription_id is not None,
        }

    elif event_type == "invoice.payment_failed":
        result["action"] = "mark_overdue"
        result["details"] = {
            "invoice_id": data.get("id"),
            "attempt_count": data.get("attempt_count", 0),
        }

    return result
