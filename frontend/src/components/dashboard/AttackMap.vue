<template>
  <div class="lv-card">
    <div class="lv-head">
      <div>
        <div class="lv-title">攻击来源地图</div>
        <div class="lv-sub">ECharts + GeoJSON（散点/飞线）</div>
      </div>

      <div class="lv-actions">
        <button class="lv-btn" :class="{ on: mode === 'world' }" @click="mode = 'world'">世界</button>
        <button class="lv-btn" :class="{ on: mode === 'china' }" @click="mode = 'china'">中国</button>
      </div>
    </div>

    <div class="lv-body">
      <VChart class="lv-chart" :option="option" autoresize />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import VChart from "vue-echarts";
import * as echarts from "echarts/core";
import { MapChart, LinesChart, EffectScatterChart } from "echarts/charts";
import { TooltipComponent, VisualMapComponent, GeoComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";

// ✅ 直接静态引入本地 GeoJSON（你已经下载到 src/assets/geo/ 里了）
import worldJson from "@/assets/geo/world.json";
import chinaJson from "@/assets/geo/china.json";

echarts.use([
  MapChart,
  LinesChart,
  EffectScatterChart,
  TooltipComponent,
  VisualMapComponent,
  GeoComponent,
  CanvasRenderer,
]);

// ✅ 只注册一次地图（避免重复注册、避免首次渲染 option 为空导致的闪烁/异常）
const MAP_KEY = {
  world: "WORLD",
  china: "CHINA",
} as const;

let __registered = false;
if (!__registered) {
  echarts.registerMap(MAP_KEY.world, worldJson as any);
  echarts.registerMap(MAP_KEY.china, chinaJson as any);
  __registered = true;
}

type Mode = "world" | "china";
const mode = ref<Mode>("world");

// 你的站点坐标（飞线终点）——先写死，后面可改成后端配置
const SITE = { name: "LogVision", coord: [116.4074, 39.9042] as [number, number] };

// ✅ 先用假数据验证链路：能出图就成功
type AttackPoint = { name: string; coord: [number, number]; count: number };
const points = ref<AttackPoint[]>([
  { name: "US · New York", coord: [-74.006, 40.7128], count: 41 },
  { name: "JP · Tokyo", coord: [139.6917, 35.6895], count: 22 },
  { name: "CN · Shanghai", coord: [121.4737, 31.2304], count: 18 },
  { name: "CN · Guangzhou", coord: [113.2644, 23.1291], count: 9 },
]);

function sizeByCount(c: number) {
  if (c >= 50) return 18;
  if (c >= 20) return 14;
  if (c >= 10) return 11;
  return 8;
}

const option = computed(() => {
  const mapName = mode.value === "world" ? MAP_KEY.world : MAP_KEY.china;
  const max = Math.max(...points.value.map((p) => p.count), 1);

  const linesData = points.value.map((p) => ({
    fromName: p.name,
    toName: SITE.name,
    coords: [p.coord, SITE.coord],
    value: p.count,
  }));

  const scatterData = points.value.map((p) => ({
    name: p.name,
    value: [...p.coord, p.count],
    symbolSize: sizeByCount(p.count),
  }));

  return {
    tooltip: {
      trigger: "item",
      formatter: (params: any) => {
        const v = params?.value;
        if (Array.isArray(v) && v.length >= 3) return `${params.name}<br/>攻击次数：${v[2]}`;
        if (params?.data?.fromName) return `${params.data.fromName} → ${params.data.toName}<br/>次数：${params.data.value}`;
        return params.name || "";
      },
    },

    // 说明：你当前没有“区域着色(series-map)”的数据，所以 visualMap 只会显示刻度，不会给地图上色
    visualMap: {
      min: 0,
      max,
      calculable: true,
      left: 12,
      bottom: 12,
      text: ["高", "低"],
    },

    geo: {
      map: mapName,
      roam: true,
      zoom: mode.value === "china" ? 1.2 : 1,
      itemStyle: { borderWidth: 0.8, opacity: 0.95 },
      emphasis: { label: { show: false } },
    },

    series: [
      {
        type: "lines",
        coordinateSystem: "geo",
        zlevel: 2,
        effect: { show: true, symbolSize: 6 },
        lineStyle: { width: 1, opacity: 0.6, curveness: 0.2 },
        data: linesData,
      },
      {
        type: "effectScatter",
        coordinateSystem: "geo",
        zlevel: 3,
        rippleEffect: { brushType: "stroke" },
        data: scatterData,
      },
      {
        type: "scatter",
        coordinateSystem: "geo",
        zlevel: 4,
        symbolSize: 14,
        data: [{ name: SITE.name, value: [...SITE.coord, 999] }],
      },
    ],
  };
});
</script>

<style scoped>
.lv-card {
  border-radius: 16px;
  padding: 14px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.lv-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.lv-title {
  font-size: 16px;
  font-weight: 700;
}

.lv-sub {
  font-size: 12px;
  opacity: 0.7;
  margin-top: 2px;
}

.lv-actions {
  display: flex;
  gap: 8px;
}

.lv-btn {
  padding: 6px 10px;
  border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: transparent;
  cursor: pointer;
  opacity: 0.85;
}

.lv-btn.on {
  opacity: 1;
  border-color: rgba(255, 255, 255, 0.35);
}

.lv-body {
  height: 420px;
}

.lv-chart {
  width: 100%;
  height: 100%;
}
</style>
