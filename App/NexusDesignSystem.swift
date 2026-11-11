import SwiftUI
import Charts
import UIKit
import NexusCore

enum NexusPalette {
    static let background = adaptive(light: 0xEEF3FB, dark: 0x070C18)
    static let surface = adaptive(light: 0xFFFFFF, dark: 0x172137)
    static let elevatedSurface = adaptive(light: 0xEDF1F7, dark: 0x202B42)
    static let border = adaptive(light: 0xDCE3ED, dark: 0x28354A)
    static let primaryText = adaptive(light: 0x152033, dark: 0xFFFFFF)
    static let secondaryText = adaptive(light: 0x56647A, dark: 0xA6AFC2)
    static let blue = adaptive(light: 0x426FCB, dark: 0x9CBCFF)
    static let purple = adaptive(light: 0x8057C7, dark: 0xC9ADFF)
    static let green = adaptive(light: 0x258D72, dark: 0x7CE8CA)
    static let amber = adaptive(light: 0xA76A22, dark: 0xF1C07E)
    static let red = adaptive(light: 0xB83D4C, dark: 0xFF93A2)

    private static func adaptive(light: UInt32, dark: UInt32) -> Color {
        Color(uiColor: UIColor { traits in
            let value = traits.userInterfaceStyle == .dark ? dark : light
            return UIColor(
                red: CGFloat((value >> 16) & 0xFF) / 255,
                green: CGFloat((value >> 8) & 0xFF) / 255,
                blue: CGFloat(value & 0xFF) / 255,
                alpha: 1)
        })
    }
}

enum NexusLayout {
    static let microSpacing: CGFloat = 4
    static let compactSpacing: CGFloat = 8
    static let standardSpacing: CGFloat = 11
    static let sectionSpacing: CGFloat = 11
    static let screenInset: CGFloat = 14
    static let cardPadding: CGFloat = 15
    static let cardCornerRadius: CGFloat = 26
    static let compactCardHeight: CGFloat = 44
}

enum NexusTypography {
    static let sectionTitle = Font.system(.subheadline).weight(.semibold)
    static let cardTitle = Font.system(.subheadline).weight(.semibold)
    static let supporting = Font.system(.footnote)
    static let caption = Font.system(.caption).weight(.medium)
    static let monospaced = Font.system(.caption, design: .monospaced)
}

enum NexusStatusTone {
    case positive
    case caution
    case critical
    case neutral

    var color: Color {
        switch self {
        case .positive: NexusPalette.green
        case .caution: NexusPalette.amber
        case .critical: NexusPalette.red
        case .neutral: NexusPalette.secondaryText
        }
    }
}

struct NexusCard<Content: View>: View {
    var padding: CGFloat = NexusLayout.cardPadding
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(NexusGlassSurface(cornerRadius: NexusLayout.cardCornerRadius))
    }
}

/// Midnight Glass card surface: white glass over the dark backdrop, with a lit
/// top edge and a diagonal sheen. Nothing but the backdrop sits behind a card,
/// so it needs no blur, and a grey material would wash out the blue depth.
struct NexusGlassSurface: View {
    var corners: RectangleCornerRadii
    /// Off for surfaces that resize constantly, where a blurred shadow is costly.
    var showsShadow = true
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorScheme) private var colorScheme

    init(cornerRadius: CGFloat = NexusLayout.cardCornerRadius) {
        corners = RectangleCornerRadii(topLeading: cornerRadius, bottomLeading: cornerRadius,
                                       bottomTrailing: cornerRadius, topTrailing: cornerRadius)
    }

    init(corners: RectangleCornerRadii, showsShadow: Bool = true) {
        self.corners = corners
        self.showsShadow = showsShadow
    }

    var body: some View {
        let shape = UnevenRoundedRectangle(cornerRadii: corners, style: .continuous)
        let dark = colorScheme == .dark
        if reduceTransparency {
            shape.fill(NexusPalette.surface)
                .overlay { shape.strokeBorder(NexusPalette.border, lineWidth: 1) }
        } else {
            shape
                .fill(LinearGradient(stops: [
                    .init(color: .white.opacity(dark ? 0.13 : 0.62), location: 0),
                    .init(color: .white.opacity(dark ? 0.075 : 0.42), location: 0.42),
                    .init(color: .white.opacity(dark ? 0.075 : 0.42), location: 1)
                ], startPoint: .topLeading, endPoint: .bottomTrailing))
                .overlay {
                    shape.fill(LinearGradient(stops: [
                        .init(color: .white.opacity(dark ? 0.2 : 0.3), location: 0),
                        .init(color: .clear, location: 0.26),
                        .init(color: .clear, location: 0.72),
                        .init(color: .white.opacity(dark ? 0.09 : 0.14), location: 1)
                    ], startPoint: .topLeading, endPoint: .bottomTrailing))
                }
                .overlay {
                    shape.strokeBorder(LinearGradient(colors: [
                        .white.opacity(dark ? 0.27 : 0.95),
                        .white.opacity(dark ? 0.08 : 0.3),
                        .white.opacity(dark ? 0.08 : 0.3)
                    ], startPoint: .top, endPoint: .bottom), lineWidth: 1)
                }
                .shadow(color: showsShadow ? Color(red: 3 / 255, green: 8 / 255, blue: 24 / 255)
                            .opacity(dark ? 0.42 : 0.14) : .clear,
                        radius: showsShadow ? 17 : 0, x: 0, y: showsShadow ? 14 : 0)
        }
    }
}

/// Floating controls: Apple's Liquid Glass on iOS 26, the card surface before it.
private struct NexusLiquidGlass: ViewModifier {
    let cornerRadius: CGFloat
    let tint: Color?
    let interactive: Bool
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        if #available(iOS 26, *), !reduceTransparency {
            content.glassEffect(glass, in: .rect(cornerRadius: cornerRadius, style: .continuous))
        } else {
            content.background(NexusGlassSurface(cornerRadius: cornerRadius))
        }
    }

    @available(iOS 26, *)
    private var glass: Glass {
        // A faint white tint lifts controls to the same brightness as cards.
        let base = Glass.regular.tint(tint ?? .white.opacity(0.1))
        return interactive ? base.interactive() : base
    }
}

/// Static midnight depth behind every screen: near-black with three contained
/// glows. Static gradients avoid the GPU cost of continuous motion.
struct NexusBackdrop: View {
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let dark = colorScheme == .dark
        GeometryReader { proxy in
            let size = proxy.size
            ZStack {
                NexusPalette.background
                glow(dark ? 0x27457F : 0xA9C6FF, x: 0.8, y: 0.04, width: 0.46, height: 0.25, in: size)
                glow(dark ? 0x1B3A63 : 0xA9F1DD, x: 0.04, y: 0.58, width: 0.53, height: 0.264, in: size)
                glow(dark ? 0x34276E : 0xDCC4FF, x: 0.9, y: 1, width: 0.46, height: 0.224, in: size)
            }
        }
        .clipped()
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }

    /// `width` and `height` are the ellipse's radii as fractions of the screen.
    private func glow(_ hex: UInt32, x: CGFloat, y: CGFloat, width: CGFloat, height: CGFloat,
                      in size: CGSize) -> some View {
        let color = Color(red: Double(hex >> 16 & 0xFF) / 255, green: Double(hex >> 8 & 0xFF) / 255,
                          blue: Double(hex & 0xFF) / 255)
        return RadialGradient(colors: [color, color.opacity(0)], center: .center,
                              startRadius: 0, endRadius: 100)
            .frame(width: 200, height: 200)
            .scaleEffect(x: size.width * width / 100, y: size.height * height / 100)
            .position(x: size.width * x, y: size.height * y)
    }
}

/// Translucent row fill shared by every grouped list and form.
struct NexusGlassRowBackground: View {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        if reduceTransparency {
            NexusPalette.surface
        } else {
            Color.white.opacity(colorScheme == .dark ? 0.085 : 0.55)
        }
    }
}

/// `List` on the Midnight Glass backdrop.
struct NexusList<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        List {
            Group { content }.listRowBackground(NexusGlassRowBackground())
        }
        .scrollContentBackground(.hidden)
        .contentMargins(.horizontal, NexusLayout.screenInset, for: .scrollContent)
        .listSectionSpacing(NexusLayout.sectionSpacing)
        .background(NexusBackdrop())
    }
}

/// `Form` on the Midnight Glass backdrop.
struct NexusForm<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        Form {
            Group { content }.listRowBackground(NexusGlassRowBackground())
        }
        .scrollContentBackground(.hidden)
        .contentMargins(.horizontal, NexusLayout.screenInset, for: .scrollContent)
        .listSectionSpacing(NexusLayout.sectionSpacing)
        .background(NexusBackdrop())
    }
}

/// Title block at the top of each tab, with an optional round control beside it.
struct NexusScreenHeader<Trailing: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder var trailing: Trailing
    @ScaledMetric(relativeTo: .largeTitle) private var titleSize: CGFloat = 31

    var body: some View {
        HStack(spacing: NexusLayout.standardSpacing) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: titleSize, weight: .bold))
                    .tracking(-0.4)
                    .foregroundStyle(NexusPalette.primaryText)
                    .accessibilityAddTraits(.isHeader)
                Text(subtitle)
                    .font(NexusTypography.supporting)
                    .foregroundStyle(NexusPalette.secondaryText)
            }
            Spacer(minLength: 0)
            trailing
        }
        .padding(.horizontal, NexusLayout.microSpacing)
        .padding(.top, NexusLayout.microSpacing)
        .padding(.bottom, 2)
    }
}

extension NexusScreenHeader where Trailing == EmptyView {
    init(title: String, subtitle: String) {
        self.init(title: title, subtitle: subtitle) { EmptyView() }
    }
}

/// Round glass label for a header button.
struct NexusRoundGlassLabel: View {
    let systemImage: String

    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: 17, weight: .semibold))
            .foregroundStyle(NexusPalette.blue)
            .frame(width: 44, height: 44)
            .nexusGlass(cornerRadius: 22, interactive: true)
            .contentShape(Circle())
    }
}

/// Rounded icon tile used in list rows.
struct NexusIconTile: View {
    let systemImage: String
    var tint: Color = NexusPalette.blue
    var size: CGFloat = 38

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.34, style: .continuous)
        Image(systemName: systemImage)
            .font(.system(size: size * 0.46, weight: .semibold))
            .foregroundStyle(tint)
            .frame(width: size, height: size)
            .background(.white.opacity(0.13), in: shape)
            .overlay {
                shape.strokeBorder(LinearGradient(colors: [.white.opacity(0.27), .clear],
                                                  startPoint: .top, endPoint: .bottom), lineWidth: 1)
            }
            .accessibilityHidden(true)
    }
}

/// Status light. Only measured states glow.
struct NexusStatusDot: View {
    let color: Color
    var glows = true

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 8, height: 8)
            .shadow(color: glows ? color : .clear, radius: 5)
            .accessibilityHidden(true)
    }
}

/// Several rows sharing one glass panel.
struct NexusGlassGroup<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) { content }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(NexusGlassSurface())
    }
}

struct NexusGlassDivider: View {
    var body: some View {
        Rectangle().fill(.white.opacity(0.08)).frame(height: 1).accessibilityHidden(true)
    }
}

struct NexusSectionHeader: View {
    let title: String
    var subtitle: String? = nil
    var trailing: String? = nil

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: NexusLayout.compactSpacing) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(NexusTypography.sectionTitle).foregroundStyle(NexusPalette.primaryText)
                if let subtitle {
                    Text(subtitle).font(NexusTypography.caption).foregroundStyle(NexusPalette.secondaryText)
                }
            }
            Spacer(minLength: 0)
            if let trailing {
                Text(trailing).font(NexusTypography.caption).foregroundStyle(NexusPalette.secondaryText)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// `value` is nil when nothing was measured, so no number is shown.
struct NexusMetricCard: View {
    let title: String
    let value: String?
    let detail: String
    let systemImage: String
    let tint: Color
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @ScaledMetric(relativeTo: .title) private var valueSize: CGFloat = 27

    var body: some View {
        NexusCard {
            VStack(alignment: .leading, spacing: NexusLayout.compactSpacing) {
                Image(systemName: systemImage)
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundStyle(tint)
                    .frame(height: 22)
                VStack(alignment: .leading, spacing: 1) {
                    Text(value ?? "—")
                        .font(.system(size: valueSize, weight: .bold))
                        .tracking(-0.4)
                        .monospacedDigit()
                        .foregroundStyle(NexusPalette.primaryText)
                        .contentTransition(reduceMotion ? .identity : .numericText())
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                    Text(title)
                        .font(NexusTypography.caption)
                        .foregroundStyle(NexusPalette.secondaryText)
                    // Always laid out so every card in the grid has the same height.
                    Text(detail.isEmpty ? " " : detail)
                        .font(.caption2)
                        .foregroundStyle(NexusPalette.secondaryText.opacity(0.8))
                        .lineLimit(dynamicTypeSize.isAccessibilitySize ? 3 : 1)
                        .minimumScaleFactor(0.8)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title), \(value ?? "not measured"). \(detail)")
    }
}

struct NexusStatusBadge: View {
    let title: String
    let systemImage: String
    let tone: NexusStatusTone

    var body: some View {
        Label(title, systemImage: systemImage)
            .font(.caption.weight(.medium))
            .foregroundStyle(tone.color)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(tone.color.opacity(0.13), in: Capsule())
            .overlay(Capsule().strokeBorder(tone.color.opacity(0.20), lineWidth: 1))
            .accessibilityElement(children: .combine)
    }
}

struct NexusStateCard: View {
    let title: String
    let detail: String
    let systemImage: String
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil

    var body: some View {
        NexusCard {
            VStack(alignment: .leading, spacing: NexusLayout.standardSpacing) {
                Label(title, systemImage: systemImage)
                    .font(NexusTypography.cardTitle)
                    .foregroundStyle(NexusPalette.primaryText)
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(NexusPalette.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                if let actionTitle, let action {
                    Button(actionTitle, action: action)
                        .buttonStyle(.borderedProminent)
                        .tint(NexusPalette.blue)
                        .frame(minHeight: 44)
                }
            }
        }
    }
}

/// Sparkline of measured CPU samples.
struct NexusCPUActivityChart: View {
    let history: [HostMetricsHistoryRecord]
    var window: TimeInterval = 60
    var now: Date = .now

    private var cpuSamples: [(date: Date, value: Double)] {
        history
            .filter { $0.snapshot.observedAt >= now.addingTimeInterval(-window) && $0.snapshot.observedAt <= now }
            .sorted { $0.snapshot.observedAt < $1.snapshot.observedAt }
            .compactMap { record in
                guard let value = record.snapshot.cpuUtilizationPercent,
                      value.isFinite, (0...100).contains(value) else { return nil }
                return (record.snapshot.observedAt, value)
            }
    }

    var body: some View {
        if cpuSamples.isEmpty {
            Text("No samples in the last minute")
                .font(NexusTypography.supporting)
                .foregroundStyle(NexusPalette.secondaryText)
                .frame(maxWidth: .infinity, minHeight: 62, alignment: .leading)
        } else {
            Chart {
                ForEach(Array(cpuSamples.enumerated()), id: \.offset) { _, sample in
                    AreaMark(x: .value("Time", sample.date), y: .value("CPU", sample.value))
                        .foregroundStyle(LinearGradient(colors: [NexusPalette.blue.opacity(0.22), NexusPalette.blue.opacity(0)],
                            startPoint: .top, endPoint: .bottom))
                        .interpolationMethod(.catmullRom)
                    LineMark(x: .value("Time", sample.date), y: .value("CPU", sample.value))
                        .foregroundStyle(NexusPalette.blue)
                        .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                        .interpolationMethod(.catmullRom)
                }
                if cpuSamples.count == 1, let sample = cpuSamples.first {
                    PointMark(x: .value("Time", sample.date), y: .value("CPU", sample.value))
                        .foregroundStyle(NexusPalette.blue)
                }
            }
            .chartYScale(domain: 0...100)
            .chartYAxis(.hidden)
            .chartXAxis(.hidden)
            .frame(height: 62)
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("CPU activity over the last minute")
            .accessibilityValue(cpuSamples.last.map { "Latest measured CPU utilization \(Int($0.value.rounded())) percent" } ?? "No samples")
        }
    }
}

private struct NexusMatteSurface: ViewModifier {
    var padding: CGFloat = NexusLayout.cardPadding

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(NexusGlassSurface())
    }
}

extension View {
    func nexusMatteSurface(padding: CGFloat = NexusLayout.cardPadding) -> some View {
        modifier(NexusMatteSurface(padding: padding))
    }

    /// Liquid Glass for a floating control or panel.
    func nexusGlass(cornerRadius: CGFloat = NexusLayout.cardCornerRadius, tint: Color? = nil,
                    interactive: Bool = false) -> some View {
        modifier(NexusLiquidGlass(cornerRadius: cornerRadius, tint: tint, interactive: interactive))
    }

    func nexusScreenBackground() -> some View {
        background(NexusBackdrop())
    }
}
