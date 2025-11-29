# core/views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail, EmailMessage, BadHeaderError
from django.conf import settings
from django.http import Http404
from django.utils import timezone
import hashlib, secrets, datetime, textwrap, random, re
from base64 import urlsafe_b64encode, urlsafe_b64decode
from django.core.paginator import Paginator
from .forms import SignupForm, ForgotPasswordForm, ResetPasswordForm
from .models import PasswordResetToken
from .models import Ticket
from django.db.models import Q
from django.utils.dateparse import parse_date, parse_datetime
from decimal import Decimal, InvalidOperation

from .forms import SignupForm, ForgotPasswordForm, ResetPasswordForm, VooAdminForm
from .models import PasswordResetToken, Ticket, Voo
import hashlib, secrets, datetime, textwrap
from base64 import urlsafe_b64encode, urlsafe_b64decode

User = get_user_model()

@login_required
def historico(request):
    qs = Ticket.objects.filter(user=request.user).order_by('-partida')

    # --- parâmetros de filtro (GET) ---
    q = (request.GET.get('q') or '').strip()
    status = (request.GET.get('status') or '').strip().upper()
    dfrom = request.GET.get('from') or ''   # data de ida (>=)
    dto   = request.GET.get('to') or ''     # data de volta (<=) — aqui vamos usar como limite superior da PARTIDA

    if q:
        qs = qs.filter(
            Q(codigo__icontains=q) |
            Q(origem__icontains=q) |
            Q(destino__icontains=q) |
            Q(companhia__icontains=q)
        )

    if status:
        qs = qs.filter(status=status)

    if dfrom:
        df = parse_date(dfrom)
        if df:
            qs = qs.filter(partida__date__gte=df)

    if dto:
        dt = parse_date(dto)
        if dt:
            qs = qs.filter(partida__date__lte=dt)

    # (opcional) paginação
    from django.core.paginator import Paginator
    paginator = Paginator(qs, 10)
    page_obj = paginator.get_page(request.GET.get('page'))

    ctx = {
        'tickets': page_obj.object_list,
        'page_obj': page_obj,
        'total': qs.count(),
        'filters': {'q': q, 'from': dfrom, 'to': dto, 'status': status},
    }
    return render(request, "historico.html", ctx)

# ---------------------- PÁGINAS PRINCIPAIS ----------------------
def home(request): return render(request, "home.html")
def resultados(request):
    ctx = {
        "default_origem": request.GET.get("origem", ""),
        "default_destino": request.GET.get("destino", ""),
        "default_data": request.GET.get("data", ""),
        "default_volta": request.GET.get("volta", ""),
        "default_pax": request.GET.get("pax", ""),
    }
    return render(request, "resultados.html", ctx)

def contato(request):
    context = {"errors": {}, "data": {}}
    if request.method == "POST":
        nome = request.POST.get("nome", "").strip()
        email = request.POST.get("email", "").strip()
        assunto = request.POST.get("assunto", "").strip()
        mensagem = request.POST.get("mensagem", "").strip()
        context["data"] = {"nome": nome, "email": email, "assunto": assunto, "mensagem": mensagem}

        if not nome: context["errors"]["nome"] = "Informe seu nome."
        if not email:
            context["errors"]["email"] = "Informe seu e-mail."
        else:
            try: validate_email(email)
            except ValidationError: context["errors"]["email"] = "E-mail inválido."
        if not assunto: context["errors"]["assunto"] = "Informe um assunto."
        if not mensagem or len(mensagem) < 10:
            context["errors"]["mensagem"] = "Escreva uma mensagem (mínimo 10 caracteres)."

        if not context["errors"]:
            try:
                corpo_admin = textwrap.dedent(f"""
                Nova mensagem de contato no FlyTrack:

                Nome: {nome}
                E-mail: {email}
                Assunto: {assunto}

                Mensagem:
                {mensagem}
                """)
                EmailMessage(
                    subject=f"[FlyTrack] Contato: {assunto}",
                    body=corpo_admin,
                    from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                    to=[getattr(settings, "CONTACT_TO_EMAIL", settings.EMAIL_HOST_USER)],
                    reply_to=[email] if email else None,
                ).send(fail_silently=False)

                send_mail(
                    subject="Recebemos sua mensagem — FlyTrack",
                    message=textwrap.dedent(f"Olá, {nome}!\n\nRecebemos sua mensagem e responderemos em breve.\n\nAssunto: {assunto}\n\n— Equipe FlyTrack"),
                    from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                    recipient_list=[email],
                    fail_silently=True,
                )
                context["success"] = True
                context["data"] = {}
            except BadHeaderError:
                context["errors"]["assunto"] = "Assunto inválido."
            except Exception:
                context["errors"]["global"] = "Não foi possível enviar sua mensagem agora. Tente novamente mais tarde."
    return render(request, "contato.html", context)

# ---------------------- AUTENTICAÇÃO ----------------------
def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f"Olá {user.get_full_name() or user.username} — conta criada e login realizado.")
            return redirect("core:post_login")
    else:
        form = SignupForm()
    return render(request, "registration/signup.html", {"form": form})

def login_view(request):
    form = AuthenticationForm(request, data=request.POST or None)
    next_url = request.GET.get("next") or request.POST.get("next") or ""  # <<< garante string

    if request.method == "POST":
        if form.is_valid():
            user = form.get_user()
            login(request, user)

            if not request.POST.get("remember_me"):
                request.session.set_expiry(0)

            if next_url:
                return redirect(next_url)

            if user.is_staff or user.is_superuser:
                return redirect("core:admin_home")
            return redirect("core:home")
        else:
            print("[LOGIN] form errors:", form.errors)

    return render(request, "registration/login.html", {"form": form, "next": next_url})


def logout_view(request):
    logout(request)
    messages.info(request, "Você saiu da conta.")
    return redirect("core:home")

@login_required
def post_login(request):
    if request.user.is_staff or request.user.is_superuser:
        return redirect("core:admin_home")
    return redirect("core:home")

# ---------------------- ADMIN (somente staff/superuser) ----------------------
def _staff_access(user):
    return user.is_staff or user.is_superuser


@login_required
@user_passes_test(_staff_access, login_url="core:home")
def admin_home(request):
    ctx = {"sucesso": request.method == "POST", "active_nav": "dashboard"}
    return render(request, "admin/adm_home.html", ctx)


@login_required
@user_passes_test(_staff_access, login_url="core:home")
def admin_passageiros(request):
    return render(request, "admin/passageiros.html", {"active_nav": "passageiros"})


@login_required
@user_passes_test(_staff_access, login_url="core:home")
def admin_voos(request):
    return render(request, "admin/voos.html", {"active_nav": "voos"})


@login_required
@user_passes_test(_staff_access, login_url="core:home")
def admin_passagens(request):
    return render(request, "admin/passagens.html", {"active_nav": "passagens"})


@login_required
@user_passes_test(_staff_access, login_url="core:home")
def admin_pagamentos(request):
    return render(request, "admin/pagamentos.html", {"active_nav": "pagamentos"})


@login_required
@user_passes_test(_staff_access, login_url="core:home")
def admin_checkin(request):
    return render(request, "admin/checkin.html", {"active_nav": "checkin"})


@login_required
@user_passes_test(_staff_access, login_url="core:home")
def admin_produtos(request):
    return render(request, "admin/produtos.html", {"active_nav": "produtos"})


@login_required
@user_passes_test(_staff_access, login_url="core:home")
def admin_configuracoes(request):
    return render(request, "admin/configuracoes.html", {"active_nav": "configuracoes"})


@login_required
def selecionar_assento(request):
    origem = request.GET.get("origem", "Origem")
    destino = request.GET.get("destino", "Destino")
    data_viagem = request.GET.get("data", "")
    tarifa = request.GET.get("tarifa", "")
    codigo = request.GET.get("codigo", "FT000")
    segmento = request.GET.get("segmento", "ida")
    try:
        pax_total = int(request.GET.get("pax", "1"))
    except (TypeError, ValueError):
        pax_total = 1
    pax_total = max(1, min(pax_total, 9))

    seat_rows = []
    blocked = {"2B", "3C", "4D", "5E", "6A"}
    preferred = {"1A", "1B", "1C", "7A", "7F"}
    for row in range(1, 11):
        seats = []
        for letter in "ABCDEF":
            label = f"{row}{letter}"
            if label in blocked:
                status = "ocupado"
            elif label in preferred:
                status = "premium"
            else:
                status = "livre"
            seats.append({"label": label, "status": status})
        seat_rows.append({"row": row, "seats": seats})

    ctx = {
        "origem": origem,
        "destino": destino,
        "data_viagem": data_viagem,
        "tarifa": tarifa,
        "codigo": codigo,
        "segmento": segmento,
        "seat_rows": seat_rows,
        "pax_total": pax_total,
    }
    return render(request, "selecionar_assento.html", ctx)


PREMIUM_SURCHARGE = Decimal("90.00")
CURRENCY_CLEAN_RE = re.compile(r"[^0-9,.-]")
PAYMENT_METHODS = {
    "cartao": {
        "label": "Cartão de crédito",
        "description": "Pague no crédito em até 12x."},
    "pix": {
        "label": "PIX",
        "description": "Aprovação instantânea com QR Code/chave."},
    "boleto": {
        "label": "Boleto bancário",
        "description": "Geramos um boleto com vencimento em 1 dia útil."},
}
PAYMENT_METHOD_CHOICES = [
    {"key": key, "title": meta["label"], "description": meta["description"]}
    for key, meta in PAYMENT_METHODS.items()
]


def _parse_currency(value: str) -> Decimal:
    if not value:
        return Decimal("0")
    cleaned = CURRENCY_CLEAN_RE.sub("", value)
    cleaned = cleaned.replace(".", "").replace(",", ".")
    try:
        return Decimal(cleaned)
    except Exception:
        return Decimal("0")


def _format_brl(amount: Decimal) -> str:
    if amount <= 0:
        return "R$ 0,00"
    return f"R$ {amount:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def _extract_summary_data(source):
    origem = source.get("origem", "Origem")
    destino = source.get("destino", "Destino")
    data_viagem = source.get("data", "")
    codigo = source.get("codigo", "FT000")
    segmento = source.get("segmento", "ida").lower()
    assentos_raw = source.get("assentos", "")
    assentos = [s.strip() for s in assentos_raw.split(",") if s.strip()]
    seat_count = len(assentos)
    pax_total = max(seat_count, 1)
    pax = source.get("pax")
    if pax is not None:
        try:
            parsed = max(1, min(int(pax), 9))
            pax_total = max(parsed, pax_total)
        except (TypeError, ValueError):
            pax_total = max(pax_total, 1)
    method_raw = (source.get("metodo_pagamento") or source.get("payment_method") or "cartao").lower()
    if method_raw not in PAYMENT_METHODS:
        method_raw = "cartao"
    tarifa_raw = source.get("tarifa", "")
    tarifa_decimal = _parse_currency(tarifa_raw)
    premium_count_raw = source.get("premium_count")
    try:
        premium_count = max(0, min(int(premium_count_raw), 9)) if premium_count_raw is not None else 0
    except (TypeError, ValueError):
        premium_count = 0
    premium_total = PREMIUM_SURCHARGE * premium_count
    total_raw = source.get("total", "")
    total_decimal = _parse_currency(total_raw)
    if tarifa_decimal <= 0 and total_decimal > 0:
        tarifa_decimal = max(total_decimal - premium_total, Decimal("0"))
    total_valor = total_decimal if total_decimal > 0 else tarifa_decimal + premium_total
    return {
        "origem": origem,
        "destino": destino,
        "data_viagem": data_viagem,
        "codigo": codigo,
        "segmento": segmento,
        "pax_total": pax_total,
        "tarifa_fmt": _format_brl(tarifa_decimal),
        "tarifa_valor": tarifa_decimal,
        "assentos": assentos,
        "premium_count": premium_count,
        "premium_total": premium_total,
        "premium_total_fmt": _format_brl(premium_total) if premium_total > 0 else "R$ 0,00",
        "total_valor": total_valor,
        "total_fmt": _format_brl(total_valor) if total_valor > 0 else _format_brl(tarifa_decimal),
        "has_premium": premium_count > 0,
        "metodo_pagamento": method_raw,
        "metodo_pagamento_label": PAYMENT_METHODS[method_raw]["label"],
    }


def _summary_for_session(summary: dict) -> dict:
    safe_summary = summary.copy()
    for key in ("tarifa_valor", "premium_total", "total_valor"):
        valor = safe_summary.get(key)
        if isinstance(valor, Decimal):
            safe_summary[key] = str(valor)
    return safe_summary


def _parse_partida_datetime(value: str):
    dt = None
    if value:
        dt = parse_datetime(value)
        if not dt:
            parsed_date = parse_date(value)
            if parsed_date:
                dt = datetime.datetime.combine(parsed_date, datetime.time(9, 0))
    if not dt:
        dt = timezone.now()
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return dt


def _ensure_decimal(value) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if value is None:
        return Decimal("0")
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal("0")


def _persist_ticket(request, summary: dict, localizador: str):
    if not request.user.is_authenticated:
        return

    partida = _parse_partida_datetime(summary.get("data_viagem"))
    chegada = partida + datetime.timedelta(hours=8)
    preco = _ensure_decimal(summary.get("total_valor"))
    if preco <= 0:
        preco = _ensure_decimal(summary.get("tarifa_valor"))
    if preco <= 0 and summary.get("tarifa_fmt"):
        preco = _parse_currency(summary.get("tarifa_fmt"))

    assentos_data = summary.get("assentos") or []
    if isinstance(assentos_data, str):
        assentos_str = assentos_data
    else:
        assentos_str = ", ".join(assentos_data)

    try:
        Ticket.objects.create(
            user=request.user,
            codigo=localizador,
            origem=summary.get("origem", "Origem"),
            destino=summary.get("destino", "Destino"),
            partida=partida,
            chegada=chegada,
            preco=preco,
            status="PAGO",
            assentos=assentos_str[:120],
        )
    except Exception as exc:
        print("[CHECKOUT] Não foi possível salvar o ticket:", exc)


def resumo_compra(request):
    if request.method == "POST":
        summary = _extract_summary_data(request.POST)
        request.session["checkout_summary"] = _summary_for_session(summary)
        return redirect("core:pagamento")

    summary = _extract_summary_data(request.GET)
    if not summary["assentos"]:
        messages.warning(request, "Selecione ao menos um assento antes de continuar.")
        return redirect("core:resultados")

    ctx = {
        "summary": summary,
        "total_estimado": summary.get("total_fmt") or summary["tarifa_fmt"],
        "back_url": request.META.get("HTTP_REFERER") or reverse("core:selecionar_assento"),
        "payment_methods": PAYMENT_METHOD_CHOICES,
    }
    return render(request, "resumo_compra.html", ctx)


def pagamento(request):
    summary = request.session.get("checkout_summary")
    if not summary:
        messages.info(request, "Inicie uma nova busca para finalizar sua compra.")
        return redirect("core:home")

    metodo_pagamento = summary.get("metodo_pagamento", "cartao")
    if metodo_pagamento not in PAYMENT_METHODS:
        metodo_pagamento = "cartao"
    summary["metodo_pagamento"] = metodo_pagamento
    summary["metodo_pagamento_label"] = PAYMENT_METHODS[metodo_pagamento]["label"]
    requires_card = metodo_pagamento == "cartao"
    errors = {}
    data = {"nome": "", "cpf": "", "cartao": "", "validade": "", "cvv": ""} if requires_card else {}

    if request.method == "POST":
        if requires_card:
            for field in data.keys():
                data[field] = request.POST.get(field, "").strip()

            if not data["nome"]:
                errors["nome"] = "Informe o titular do cartão."
            if not data["cpf"] or len(re.sub(r"\D", "", data["cpf"])) != 11:
                errors["cpf"] = "CPF inválido."
            if not data["cartao"] or len(re.sub(r"\D", "", data["cartao"])) < 13:
                errors["cartao"] = "Número do cartão inválido."
            if not data["validade"]:
                errors["validade"] = "Informe a validade."
            if not data["cvv"] or len(data["cvv"]) not in (3, 4):
                errors["cvv"] = "CVV inválido."

        if not requires_card or not errors:
            localizador = f"FT{random.randint(100000, 999999)}"
            if requires_card:
                payer_name = data["nome"]
            else:
                payer_name = request.user.get_full_name() or request.user.username or "Cliente FlyTrack"
            checkout_result = {
                "localizador": localizador,
                "nome": payer_name,
                "summary": summary,
            }
            request.session["checkout_result"] = checkout_result
            request.session.pop("checkout_summary", None)
            try:
                _persist_ticket(request, summary, localizador)
            except Exception:
                pass
            messages.success(request, "Pagamento aprovado!")
            return redirect("core:confirmacao")

    context = {
        "summary": summary,
        "errors": errors,
        "form": data,
        "requires_card": requires_card,
        "payment_method": metodo_pagamento,
        "method_info": PAYMENT_METHODS[metodo_pagamento],
    }
    return render(request, "pagamento.html", context)


def confirmacao(request):
    checkout_result = request.session.get("checkout_result")
    summary = (checkout_result or {}).get("summary")
    if not checkout_result or not summary:
        messages.info(request, "Inicie uma nova compra para acessar esta página.")
        return redirect("core:home")

    if request.user.is_authenticated:
        fallback_passageiro = request.user.get_full_name() or request.user.get_username()
    else:
        fallback_passageiro = "Cliente Fly Track"

    context = {
        "localizador": checkout_result["localizador"],
        "summary": summary,
        "passageiro": checkout_result.get("nome") or fallback_passageiro,
    }
    request.session.pop("checkout_result", None)
    return render(request, "confirmacao.html", context)

# ---------------------- ESQUECI MINHA SENHA ----------------------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def forgot_password(request):
    if request.method == "POST":
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                return redirect("core:password_reset_done")

            PasswordResetToken.objects.filter(
                user=user, used_at__isnull=True, expires_at__lt=timezone.now()
            ).delete()

            raw_token = secrets.token_urlsafe(32)
            token_hash = _hash_token(raw_token)
            expires = timezone.now() + datetime.timedelta(hours=2)

            PasswordResetToken.objects.create(
                user=user,
                token_hash=token_hash,
                expires_at=expires,
                request_ip=(request.META.get("REMOTE_ADDR") or None),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
            )

            uidb64 = urlsafe_b64encode(str(user.pk).encode()).decode()
            reset_url = request.build_absolute_uri(
                reverse("core:password_reset_confirm", args=[uidb64, raw_token])
            )

            subject = "Redefinição de senha — Fly Track"
            body = (
                "Olá,\n\n"
                "Recebemos uma solicitação para redefinir a sua senha no Fly Track.\n"
                f"Use o link abaixo (válido por 2 horas):\n\n{reset_url}\n\n"
                "Se você não solicitou, ignore este e-mail.\n\n"
                "— Equipe Fly Track"
            )
            try:
                send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
            except BadHeaderError:
                pass

            return redirect("core:password_reset_done")
    else:
        form = ForgotPasswordForm()

    return render(request, "password_reset.html", {"form": form})

def reset_password_confirm(request, uidb64: str, token: str):
    try:
        uid = int(urlsafe_b64decode(uidb64.encode()).decode())
        user = User.objects.get(pk=uid)
    except Exception:
        raise Http404("Link inválido")

    token_hash = _hash_token(token)
    try:
        prt = PasswordResetToken.objects.get(user=user, token_hash=token_hash, used_at__isnull=True)
    except PasswordResetToken.DoesNotExist:
        raise Http404("Link inválido ou já utilizado")

    if timezone.now() > prt.expires_at:
        messages.error(request, "Este link expirou. Solicite uma nova redefinição.")
        return redirect("core:password_reset")

    if request.method == "POST":
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data["new_password"]
            user.set_password(new_password)
            user.save()
            prt.used_at = timezone.now()
            prt.save(update_fields=["used_at"])
            PasswordResetToken.objects.filter(user=user, used_at__isnull=True).update(used_at=timezone.now())
            return redirect("core:password_reset_complete")
    else:
        form = ResetPasswordForm()

    return render(request, "password_reset_confirm.html", {"form": form, "user": user})
@login_required
@user_passes_test(lambda u: u.is_staff)
def admin_home(request):
    return render(request, "admin/adm_home.html")



@user_passes_test(lambda u: u.is_staff)
def adicionar_passagem(request):

    voos_disponiveis = Voo.objects.all().order_by('-criado_em')

    if request.method == 'POST':
        form = VooAdminForm(request.POST)
        if form.is_valid():
            voo = form.save()
            messages.success(request, f"Voo {voo.codigo} cadastrado e disponível para venda!")
            return redirect('core:adicionar_passagem') # Recarrega a mesma página para ver a tabela atualizada
    else:
        form = VooAdminForm()
    

    return render(request, 'admin/adicionar_passagem.html', {
        'form': form, 
        'voos': voos_disponiveis
    })

def reset_password_done(request): return render(request, "password_reset_done.html")
def reset_password_complete(request): return render(request, "password_reset_complete.html")
