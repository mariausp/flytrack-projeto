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
from django.core.paginator import Paginator
from django.db.models import Q
from django.utils.dateparse import parse_date, parse_datetime
from django.template.loader import render_to_string
from django.utils.html import strip_tags

import hashlib
import secrets
import datetime
import textwrap
import random
import re
from base64 import urlsafe_b64encode, urlsafe_b64decode
from decimal import Decimal, InvalidOperation

from .forms import SignupForm, ForgotPasswordForm, ResetPasswordForm
from .models import PasswordResetToken, Ticket

User = get_user_model()


# ---------------------- HISTÓRICO ----------------------
# ---------------------- HISTÓRICO ----------------------
@login_required
def historico(request):
    qs = Ticket.objects.filter(user=request.user).order_by('-partida')

    # parâmetros de filtro (GET)
    q = (request.GET.get('q') or '').strip()
    status = (request.GET.get('status') or '').strip().upper()
    dfrom_str = (request.GET.get('from') or '').strip()
    dto_str   = (request.GET.get('to') or '').strip()

    # busca por texto
    if q:
        qs = qs.filter(
            Q(codigo__icontains=q) |
            Q(origem__icontains=q) |
            Q(destino__icontains=q) |
            Q(companhia__icontains=q)
        )

    # status
    if status:
        qs = qs.filter(status=status)

    # datas
    df = parse_date(dfrom_str) if dfrom_str else None
    dt = parse_date(dto_str)   if dto_str   else None

    if df and not dt:
        # Só "Data de Ida (de)" preenchida → APENAS aquele dia
        qs = qs.filter(partida__date=df)
    elif df and dt:
        # Intervalo "de" / "até"
        if df <= dt:
            qs = qs.filter(partida__date__range=(df, dt))
        else:
            # Se usuário inverter sem querer (de > até), cai só no dia "de"
            qs = qs.filter(partida__date=df)
    elif dt:
        # Só "até" preenchido: tudo até essa data
        qs = qs.filter(partida__date__lte=dt)

    paginator = Paginator(qs, 10)
    page_obj = paginator.get_page(request.GET.get('page'))

    ctx = {
        'tickets': page_obj.object_list,
        'page_obj': page_obj,
        'total': qs.count(),
        'filters': {
            'q': q,
            'from': dfrom_str,
            'to': dto_str,
            'status': status,
        },
    }
    return render(request, "historico.html", ctx)


# ---------------------- PÁGINAS PRINCIPAIS ----------------------
def home(request):
    return render(request, "home.html")


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
        context["data"] = {
            "nome": nome,
            "email": email,
            "assunto": assunto,
            "mensagem": mensagem,
        }

        if not nome:
            context["errors"]["nome"] = "Informe seu nome."
        if not email:
            context["errors"]["email"] = "Informe seu e-mail."
        else:
            try:
                validate_email(email)
            except ValidationError:
                context["errors"]["email"] = "E-mail inválido."
        if not assunto:
            context["errors"]["assunto"] = "Informe um assunto."
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
                    message=textwrap.dedent(
                        f"Olá, {nome}!\n\n"
                        "Recebemos sua mensagem e responderemos em breve.\n\n"
                        f"Assunto: {assunto}\n\n"
                        "— Equipe FlyTrack"
                    ),
                    from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                    recipient_list=[email],
                    fail_silently=True,
                )
                context["success"] = True
                context["data"] = {}
            except BadHeaderError:
                context["errors"]["assunto"] = "Assunto inválido."
            except Exception:
                context["errors"]["global"] = (
                    "Não foi possível enviar sua mensagem agora. "
                    "Tente novamente mais tarde."
                )
    return render(request, "contato.html", context)


# ---------------------- AUTENTICAÇÃO ----------------------
def signup(request):
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(
                request,
                f"Olá {user.get_full_name() or user.username} — conta criada e login realizado.",
            )
            return redirect("core:post_login")
    else:
        form = SignupForm()
    return render(request, "registration/signup.html", {"form": form})


def login_view(request):
    form = AuthenticationForm(request, data=request.POST or None)
    next_url = request.GET.get("next") or request.POST.get("next") or ""

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


# ---------------------- ASSENTOS ----------------------
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


# ---------------------- CHECKOUT / PAGAMENTO ----------------------
PREMIUM_SURCHARGE = Decimal("90.00")
CURRENCY_CLEAN_RE = re.compile(r"[^0-9,.-]")
PAYMENT_METHODS = {
    "cartao": {
        "label": "Cartão de crédito",
        "description": "Pague no crédito em até 12x.",
    },
    "pix": {
        "label": "PIX",
        "description": "Aprovação instantânea com QR Code/chave.",
    },
    "boleto": {
        "label": "Boleto bancário",
        "description": "Geramos um boleto com vencimento em 1 dia útil.",
    },
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

    method_raw = (
        source.get("metodo_pagamento")
        or source.get("payment_method")
        or "cartao"
    ).lower()
    if method_raw not in PAYMENT_METHODS:
        method_raw = "cartao"

    tarifa_raw = source.get("tarifa", "")
    tarifa_decimal = _parse_currency(tarifa_raw)

    premium_count_raw = source.get("premium_count")
    try:
        premium_count = (
            max(0, min(int(premium_count_raw), 9))
            if premium_count_raw is not None
            else 0
        )
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
        "premium_total_fmt": _format_brl(premium_total)
        if premium_total > 0
        else "R$ 0,00",
        "total_valor": total_valor,
        "total_fmt": _format_brl(total_valor)
        if total_valor > 0
        else _format_brl(tarifa_decimal),
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


def _send_payment_confirmation_email(user, summary: dict, localizador: str, ticket=None):
    """
    Envia e-mail de confirmação de pagamento para o usuário logado,
    com horário, regras de bagagem e recomendações.
    """
    if not user or not getattr(user, "email", None):
        return  # sem e-mail, não tem o que enviar

    nome_cliente = (
        user.get_full_name()
        or user.get_username()
        or "Cliente FlyTrack"
    )

    # horário de partida/chegada
    if ticket is not None:
        partida = ticket.partida
        chegada = ticket.chegada
    else:
        partida = _parse_partida_datetime(summary.get("data_viagem"))
        chegada = partida + datetime.timedelta(hours=8)

    if partida and timezone.is_aware(partida):
        partida_local = timezone.localtime(partida)
    else:
        partida_local = partida

    if chegada and timezone.is_aware(chegada):
        chegada_local = timezone.localtime(chegada)
    else:
        chegada_local = chegada

    partida_data = partida_local.strftime("%d/%m/%Y") if partida_local else ""
    partida_hora = partida_local.strftime("%H:%M") if partida_local else ""
    chegada_data = chegada_local.strftime("%d/%m/%Y") if chegada_local else ""
    chegada_hora = chegada_local.strftime("%H:%M") if chegada_local else ""

    assentos = summary.get("assentos") or []
    if isinstance(assentos, str):
        assentos_str = assentos
    else:
        assentos_str = ", ".join(assentos)

    valor_fmt = summary.get("total_fmt") or summary.get("tarifa_fmt")

    context = {
        "nome_cliente": nome_cliente,
        "summary": summary,
        "localizador": localizador,
        "partida_data": partida_data,
        "partida_hora": partida_hora,
        "chegada_data": chegada_data,
        "chegada_hora": chegada_hora,
        "assentos_str": assentos_str,
        "valor_fmt": valor_fmt,
    }

    subject = f"Confirmação de pagamento – Voo {summary.get('codigo', 'FlyTrack')}"

    try:
        # tenta usar template HTML (se existir)
        html_message = render_to_string(
            "core/emails/confirmacao_pagamento.html",
            context,
        )
        plain_message = strip_tags(html_message)
    except Exception as exc:
        # fallback: e-mail de texto simples
        print("[EMAIL] Erro ao renderizar template de confirmação:", exc)
        html_message = None
        plain_message = (
            f"Olá, {nome_cliente}!\n\n"
            "Seu pagamento foi confirmado. Aqui estão os detalhes da sua viagem:\n\n"
            f"Localizador: {localizador}\n"
            f"Voo: {summary.get('codigo', '')}\n"
            f"Trecho: {summary.get('origem', '')} → {summary.get('destino', '')}\n"
            f"Partida: {partida_data} às {partida_hora}\n"
            f"Chegada prevista: {chegada_data} às {chegada_hora}\n"
            f"Assentos: {assentos_str or 'A definir'}\n"
            f"Valor pago: {valor_fmt}\n\n"
            "Regras de bagagem (exemplo — consulte sempre as regras da companhia aérea):\n"
            "• Bagagem de mão: 1 peça de até 10 kg, que caiba no compartimento superior.\n"
            "• Bagagem despachada: conforme a sua tarifa; tenha o comprovante em mãos no check-in.\n"
            "• Itens proibidos: objetos cortantes, inflamáveis, aerossóis em excesso e líquidos acima do permitido na cabine.\n\n"
            "Recomendações importantes:\n"
            "• Chegue ao aeroporto com pelo menos 2 horas de antecedência para voos nacionais "
            "e 3 horas para voos internacionais.\n"
            "• Leve um documento oficial com foto e, se aplicável, passaporte válido e vistos necessários.\n"
            "• Verifique os dados da reserva (nome, data, horário e destino) antes de seguir para o embarque.\n"
            "• Guarde este e-mail: ele contém as principais informações da sua viagem.\n\n"
            "Boa viagem!\n"
            "Equipe FlyTrack"
        )

    try:
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=getattr(
                settings,
                "DEFAULT_FROM_EMAIL",
                settings.EMAIL_HOST_USER,
            ),
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
    except Exception as exc:
        print("[EMAIL] Não foi possível enviar e-mail de confirmação:", exc)


def _persist_ticket(request, summary: dict, localizador: str):
    """
    Cria o Ticket no banco e retorna a instância criada
    (ou None em caso de erro), para usar no e-mail.
    """
    if not request.user.is_authenticated:
        return None

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

    ticket = None
    try:
        ticket = Ticket.objects.create(
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

    return ticket


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

        # se for PIX/boleto OU se cartão passou nas validações
        if not requires_card or not errors:
            localizador = f"FT{random.randint(100000, 999999)}"

            if requires_card:
                payer_name = data["nome"]
            else:
                payer_name = (
                    request.user.get_full_name()
                    or request.user.username
                    or "Cliente FlyTrack"
                )

            checkout_result = {
                "localizador": localizador,
                "nome": payer_name,
                "summary": summary,
            }
            request.session["checkout_result"] = checkout_result
            request.session.pop("checkout_summary", None)

            ticket = None
            try:
                ticket = _persist_ticket(request, summary, localizador)
            except Exception:
                ticket = None

            # envia o e-mail de confirmação
            try:
                _send_payment_confirmation_email(
                    user=request.user,
                    summary=summary,
                    localizador=localizador,
                    ticket=ticket,
                )
            except Exception as exc:
                print("[CHECKOUT] Falha ao enviar e-mail de confirmação:", exc)

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
                user=user,
                used_at__isnull=True,
                expires_at__lt=timezone.now(),
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
                send_mail(
                    subject,
                    body,
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=True,
                )
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
        prt = PasswordResetToken.objects.get(
            user=user,
            token_hash=token_hash,
            used_at__isnull=True,
        )
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
            PasswordResetToken.objects.filter(
                user=user,
                used_at__isnull=True,
            ).update(used_at=timezone.now())
            return redirect("core:password_reset_complete")
    else:
        form = ResetPasswordForm()

    return render(request, "password_reset_confirm.html", {"form": form, "user": user})


def reset_password_done(request):
    return render(request, "password_reset_done.html")


def reset_password_complete(request):
    return render(request, "password_reset_complete.html")
