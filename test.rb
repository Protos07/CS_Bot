require 'telegram/bot'
require 'mechanize'
require 'nokogiri'

token = '7646243199:AAE5pE4xGMUJdfW_zzFgyp18Ja8PZajC19U'

def valid_url?(url)
  url =~ /\A(http:\/\/|https:\/\/)?([a-z0-9\-]+\.)+[a-z]{2,6}(\/\S*)?\z/i
end

class XSSScanner
  def initialize(url, chat_id, bot)
    @url = url
    @agent = Mechanize.new
    @chat_id = chat_id
    @bot = bot
  end

  def check_for_xss
    page = @agent.get(@url)
    form = page.forms.first
    vulnerabilities = []

    form.fields.each do |field|
      original_value = field.value
      field.value = "<script>alert('XSS')</script>"
      begin
        page = form.submit
        if page.body.include? "alert('XSS')"
          vulnerabilities << "XSS вразливість була знайдена #{@url} в #{field.name} полі"
        end
      rescue Mechanize::ResponseCodeError => e
        puts "Error: #{e.response_code}"
      ensure
        field.value = original_value
      end
    end

    # Відправка результатів сканування в Telegram
    if vulnerabilities.empty?
      @bot.api.send_message(chat_id: @chat_id, text: "На #{@url} вразливостей XSS не знайдено.")
    else
      @bot.api.send_message(chat_id: @chat_id, text: vulnerabilities.join("\n"))
    end
  end
end

Telegram::Bot::Client.run(token) do |bot|
  bot.listen do |message|
    case message.text
    when '/start'
      bot.api.send_message(chat_id: message.chat.id, text: "Привіт, #{message.from.first_name}! Введіть домен для сканування.")
    when '/stop'
      bot.api.send_message(chat_id: message.chat.id, text: "До побачення, #{message.from.first_name}!")
    else
      if message.entities && message.entities.any? { |entity| entity.type == 'url' }
        domain = message.text.strip
      # Додаємо http://, якщо протокол відсутній
        domain = "http://#{domain}" unless domain.start_with?('http://', 'https://')
        if valid_url?(domain)
        # Ініціалізуємо сканер XSS та виконуємо перевірку
          scanner = XSSScanner.new(domain, message.chat.id, bot)
          scanner.check_for_xss
      else
        bot.api.send_message(chat_id: message.chat.id, text: "Будь ласка, введіть дійсний домен або URL-адресу.")
      end
    end
  end
  
  end
end
