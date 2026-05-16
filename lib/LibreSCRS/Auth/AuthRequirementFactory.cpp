// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Auth/AuthRequirement.h>

#include <stdexcept>

namespace LibreSCRS::Auth {

namespace {

// PIN fields are always secret — the parameter that previously toggled
// this never had a `false` call site. Bake the invariant in.
FieldDescriptor makePinFieldNoLabel(std::string id)
{
    FieldDescriptor f;
    f.id = std::move(id);
    f.type = CredentialFieldType::NumericPin;
    f.secret = true;
    f.minLength = std::size_t{4};
    f.maxLength = std::size_t{12};
    return f;
}

FieldDescriptor makePinField(std::string id, std::string pinLabel)
{
    FieldDescriptor f = makePinFieldNoLabel(std::move(id));
    f.label.key = "librescrs.auth.label." + f.id;
    f.label.defaultText = std::move(pinLabel);
    return f;
}

FieldDescriptor makePukField()
{
    FieldDescriptor f;
    f.id = "puk";
    f.type = CredentialFieldType::AlphaNumericPuk;
    f.secret = true;
    f.minLength = std::size_t{4};
    f.maxLength = std::size_t{16};
    f.label.key = "librescrs.auth.label.puk";
    f.label.defaultText = "PUK";
    return f;
}

FieldDescriptor makeConfirmPin()
{
    FieldDescriptor f = makePinField("confirmPin", "Confirm new PIN");
    f.equalToFieldId = "newPin";
    return f;
}

// Internal helper that copies a populated `AuthRequirement` through an
// std::vector<FieldDescriptor> "build buffer" into the class's private
// storage. Because the class data is private, factories must construct
// instances inside the class itself (they're declared static on
// `AuthRequirement`) and populate via direct access. See `Builder`-style
// pattern; here we just chain returns.
//
// (Factories are class members below — they can see the private members.)

} // namespace

AuthRequirement AuthRequirement::forPreRead(PreReadAuthMethod method) noexcept
{
    AuthRequirement r;
    r.purposeValue = Purpose::PreRead;
    if (method == PreReadAuthMethod::PaceCan) {
        FieldDescriptor can;
        can.id = "can";
        can.type = CredentialFieldType::NumericCan;
        can.secret = false;
        can.minLength = std::size_t{6};
        can.maxLength = std::size_t{6};
        can.label.key = "librescrs.auth.label.can";
        can.label.defaultText = "CAN";
        r.fieldList.push_back(std::move(can));
    } else if (method == PreReadAuthMethod::BacMrz) {
        FieldDescriptor mrz;
        mrz.id = "mrz";
        mrz.type = CredentialFieldType::Mrz;
        mrz.secret = false;
        mrz.label.key = "librescrs.auth.label.mrz";
        mrz.label.defaultText = "MRZ";
        r.fieldList.push_back(std::move(mrz));
    }
    return r;
}

AuthRequirement AuthRequirement::forSigning(std::string pinLabel, int retriesLeft)
{
    if (pinLabel.empty()) {
        throw std::invalid_argument("AuthRequirement::forSigning: pinLabel must not be empty");
    }
    AuthRequirement r;
    r.purposeValue = Purpose::Signing;
    r.fieldList.push_back(makePinField("pin", std::move(pinLabel)));
    if (retriesLeft >= 0) {
        r.retriesValue = retriesLeft;
    }
    return r;
}

AuthRequirement AuthRequirement::forSigning(LocalizedText pinLabel, int retriesLeft)
{
    if (pinLabel.defaultText.empty() && pinLabel.key.empty()) {
        throw std::invalid_argument("AuthRequirement::forSigning: pinLabel.defaultText and "
                                    "pinLabel.key are both empty — at least one must be set "
                                    "so the credential prompt has a renderable label");
    }
    AuthRequirement r;
    r.purposeValue = Purpose::Signing;
    // Build the field via makePinField for the canonical numeric-PIN
    // shape (id, type, length bounds, secret bit), then override the
    // label with the caller-supplied LocalizedText so the i18n key
    // round-trips to the host instead of being synthesised from the id.
    FieldDescriptor pin = makePinField("pin", pinLabel.defaultText);
    pin.label = std::move(pinLabel);
    r.fieldList.push_back(std::move(pin));
    if (retriesLeft >= 0) {
        r.retriesValue = retriesLeft;
    }
    return r;
}

AuthRequirement AuthRequirement::forChangePin(std::string pinLabel, int retriesLeft)
{
    if (pinLabel.empty()) {
        throw std::invalid_argument("AuthRequirement::forChangePin: pinLabel must not be empty");
    }
    AuthRequirement r;
    r.purposeValue = Purpose::ChangePin;
    r.fieldList.push_back(makePinField("currentPin", std::string{"Current "} + pinLabel));
    r.fieldList.push_back(makePinField("newPin", std::string{"New "} + pinLabel));
    r.fieldList.push_back(makeConfirmPin());
    if (retriesLeft >= 0) {
        r.retriesValue = retriesLeft;
    }
    return r;
}

AuthRequirement AuthRequirement::forChangePin(LocalizedText pinLabel, int retriesLeft)
{
    if (pinLabel.defaultText.empty() && pinLabel.key.empty()) {
        throw std::invalid_argument("AuthRequirement::forChangePin: pinLabel.defaultText and "
                                    "pinLabel.key are both empty — at least one must be set "
                                    "so the credential prompt has a renderable label");
    }
    AuthRequirement r;
    r.purposeValue = Purpose::ChangePin;

    // Same LocalizedText label is applied to all three fields. Role is
    // distinguished via field id ("currentPin", "newPin", "confirmPin").
    // Hosts that want "Current X" / "New X" prefixed rendering must add
    // role-aware decoration in their own UI layer; this avoids
    // synthesising untranslatable English prefixes onto i18n-aware labels.
    FieldDescriptor cur = makePinFieldNoLabel("currentPin");
    cur.label = pinLabel;
    r.fieldList.push_back(std::move(cur));

    FieldDescriptor nu = makePinFieldNoLabel("newPin");
    nu.label = std::move(pinLabel);
    r.fieldList.push_back(std::move(nu));

    r.fieldList.push_back(makeConfirmPin());

    if (retriesLeft >= 0) {
        r.retriesValue = retriesLeft;
    }
    return r;
}

AuthRequirement AuthRequirement::forUnblockPin(std::string pinLabel)
{
    if (pinLabel.empty()) {
        throw std::invalid_argument("AuthRequirement::forUnblockPin: pinLabel must not be empty");
    }
    AuthRequirement r;
    r.purposeValue = Purpose::UnblockPin;
    r.fieldList.push_back(makePukField());
    r.fieldList.push_back(makePinField("newPin", std::string{"New "} + pinLabel));
    r.fieldList.push_back(makeConfirmPin());
    return r;
}

AuthRequirement AuthRequirement::forUnblockPin(LocalizedText pinLabel)
{
    if (pinLabel.defaultText.empty() && pinLabel.key.empty()) {
        throw std::invalid_argument("AuthRequirement::forUnblockPin: pinLabel.defaultText and "
                                    "pinLabel.key are both empty — at least one must be set "
                                    "so the credential prompt has a renderable label");
    }
    AuthRequirement r;
    r.purposeValue = Purpose::UnblockPin;
    r.fieldList.push_back(makePukField());

    FieldDescriptor nu = makePinFieldNoLabel("newPin");
    nu.label = std::move(pinLabel);
    r.fieldList.push_back(std::move(nu));

    r.fieldList.push_back(makeConfirmPin());
    return r;
}

namespace {

FieldDescriptor makePaceSecretField(PaceSecretKind kind)
{
    FieldDescriptor f;
    switch (kind) {
    case PaceSecretKind::Can:
        f.id = "can";
        f.type = CredentialFieldType::NumericCan;
        f.secret = false;
        f.minLength = std::size_t{6};
        f.maxLength = std::size_t{6};
        f.label.key = "librescrs.auth.label.can";
        f.label.defaultText = "CAN";
        break;
    case PaceSecretKind::Mrz:
        f.id = "mrz";
        f.type = CredentialFieldType::Mrz;
        f.secret = false;
        f.label.key = "librescrs.auth.label.mrz";
        f.label.defaultText = "MRZ";
        break;
    case PaceSecretKind::Pin:
        f.id = "pin";
        f.type = CredentialFieldType::NumericPin;
        f.secret = true;
        f.minLength = std::size_t{4};
        f.maxLength = std::size_t{12};
        f.label.key = "librescrs.auth.label.pin";
        f.label.defaultText = "PIN";
        break;
    case PaceSecretKind::Puk:
        f.id = "puk";
        f.type = CredentialFieldType::AlphaNumericPuk;
        f.secret = true;
        f.minLength = std::size_t{4};
        f.maxLength = std::size_t{16};
        f.label.key = "librescrs.auth.label.puk";
        f.label.defaultText = "PUK";
        break;
    }
    return f;
}

} // namespace

AuthRequirement AuthRequirement::forPaceSecret(LibreSCRS::SmartCard::AppletAid aid, PaceSecretKind kind,
                                               std::optional<int> retriesLeft, LocalizedText reasonForUser) noexcept
{
    AuthRequirement r;
    r.purposeValue = Purpose::EstablishPaceChannel;
    r.fieldList.push_back(makePaceSecretField(kind));
    r.retriesValue = retriesLeft;
    if (!reasonForUser.defaultText.empty() || !reasonForUser.key.empty()) {
        r.messageText = std::move(reasonForUser);
    }
    r.paceKindValue = kind;
    r.paceAppletValue = std::move(aid);
    return r;
}

} // namespace LibreSCRS::Auth
